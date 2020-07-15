// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include <sstream>
#include <cstdlib>
#include <csignal>
#include <ctime>
#include <sys/stat.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sys/time.h>
#include <sys/poll.h>

// LINUX ONLY FEATURE
//#ifdef HAVE_SYS_EPOLL_H
//#include <sys/epoll.h>
//#endif

#include <istream>
#include <map>
#include <memory>
#include <vector>
#include <atomic>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>

//#ifdef ENABLE_SEGV_BACKTRACE
//#include <execinfo.h>
//#include <ucontext.h>
//#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include "FatController.hpp"
#include "ConnectionHandler.hpp"
#include "DynamicURLList.hpp"
#include "DynamicIPList.hpp"
#include "String.hpp"
#include "SocketArray.hpp"
#include "UDSocket.hpp"
#include "SysV.hpp"
#include "Queue.hpp"
#include "OptionContainer.hpp"
#include "Logger.hpp"
#include "AccessLogger.hpp"

#ifdef VALGRD
  extern "C"
  {
    static void*
    execute_native_thread_routine(void* __p)
    {
      std::thread::_Impl_base* __t = static_cast<std::thread::_Impl_base*>(__p);
      std::thread::__shared_base_type __local;
      __local.swap(__t->_M_this_ptr);

      __try
	{
	  __t->_M_run();
	}
      __catch(const __cxxabiv1::__forced_unwind&)
	{
	  __throw_exception_again;
	}
      __catch(...)
	{
	  std::terminate();
	}

      return nullptr;
    }
  } // extern "C"


  void
  std::thread::_M_start_thread(__shared_base_type __b)
  {
    if (!__gthread_active_p())
#if __cpp_exceptions
      throw system_error(make_error_code(errc::operation_not_permitted),
			 "Enable multithreading to use std::thread");
#else
      __throw_system_error(int(errc::operation_not_permitted));
#endif

    _M_start_thread(std::move(__b), nullptr);
  }


  void
  std::thread::_M_start_thread(__shared_base_type __b, void (*)())
  {
    auto ptr = __b.get();
    ptr->_M_this_ptr = std::move(__b);
    int __e = __gthread_create(&_M_id._M_thread,
			       &execute_native_thread_routine, ptr);
    if (__e)
    {
      ptr->_M_this_ptr.reset();
      __throw_system_error(__e);
    }
  }

#endif

// GLOBALS

// these are used in signal handlers - "volatile" indicates they can change at
// any time, and therefore value reading on them does not get optimised. since
// the values can get altered by outside influences, this is useful.
//static volatile bool ttg = false;
std::atomic<bool> ttg;
std::atomic<bool> gentlereload;
//static volatile bool sig_term_killall = false;
std::atomic<bool> reloadconfig ;
std::atomic<int> reload_cnt;

extern OptionContainer o;

void stat_rec::clear()
{
    conx = 0;
    reqs = 0;
};

void stat_rec::start()
{
    clear();
    start_int = time(NULL);
    end_int = start_int + o.dstat_interval;
    if (o.dstat_log_flag) {
        mode_t old_umask;
        old_umask = umask(S_IWGRP | S_IWOTH);
        fs = fopen(o.dstat_location.c_str(), "a");
        if (fs) {
    	   if (o.stats_human_readable){
               fprintf(fs, "time		        httpw	busy	httpwQ	logQ	conx	conx/s	 reqs	reqs/s	maxfd	LCcnt\n");
	   } else {
               fprintf(fs, "time		httpw	busy	httpwQ	logQ	conx	conx/s	reqs	reqs/s	maxfd	LCcnt\n");
	   }
        } else {
           e2logger_error("Unable to open dstats_log '", o.dstat_location, "' for writing.Continuing without logging");
           o.dstat_log_flag = false;
        };
        maxusedfd = 0;
        fflush(fs);
        umask(old_umask);
    };
};

void stat_rec::reset()
{
    time_t now = time(NULL);
    int bc = busychildren;
    long period = now - start_int;
    long cnx = (long)conx;
    long rqx = (long) reqs;
    int mfd = maxusedfd;
    int LC = o.LC_cnt;
    // clear and reset stats now so that stats are less likely to be missed
    clear();
    if ((end_int + o.dstat_interval) > now)
        start_int = end_int;
    else
        start_int = now;

    end_int = start_int + o.dstat_interval;

    long cps = cnx / period;
    long rqs = rqx / period;
    if (o.stats_human_readable){
        struct tm * timeinfo;
        time( &now);
        timeinfo = localtime ( &now );
        char buffer [50];
        strftime (buffer,50,"%Y-%m-%d %H:%M",timeinfo);
    	fprintf(fs, "%s	%d	%d	%d	%d	%ld	%ld	%ld	 %ld	%d	 %d\n", buffer, o.http_workers,
        bc, o.http_worker_Q.size(), o.log.log_Q.size(), cnx, cps, rqx, rqs, mfd, LC);
    } else {
        fprintf(fs, "%ld	%d	%d	%d	%d	%ld	%ld	%ld	%ld	%d	%d\n", now, o.http_workers,
        bc, o.http_worker_Q.size(), o.log.log_Q.size(), cnx, cps, rqx, rqs, mfd, LC);
    }

    fflush(fs);
};

void stat_rec::close()
{
    if (fs != NULL) fclose(fs);
};


//int cache_erroring; // num cache errors reported by children
//int restart_cnt = 0;
//int restart_numchildren; // numchildren at time of gentle restart
//int hup_index;
//int gentle_to_hup = 0;

//bool gentle_in_progress = false;
int top_child_fds; // cross platform maxchildren position in children array
#ifdef HAVE_SYS_EPOLL_H
//int serversockfd; // added PIP - may need to change
#endif
int failurecount;
int serversocketcount;
SocketArray serversockets; // the sockets we will listen on for connections
Socket *peersock(NULL); // the socket which will contain the connection

//String peersockip; // which will contain the connection ip


void monitor_flag_set(bool action)
{

    String fulink = o.monitor_flag_prefix;
    String ftouch = fulink;
    if (action) {
        fulink += "paused";
        ftouch += "running";
    } else {
        fulink += "running";
        ftouch += "paused";
    }

    //mode_t old_umask;
    //old_umask = umask(S_IWOTH);
    umask(S_IWOTH);
    FILE *fs = fopen(ftouch.c_str(), "w");
    if (!fs) {
        e2logger_error( "Unable to open monitor_flag ", ftouch, " for writing");
        o.monitor_flag_flag = false;
    }
    fclose(fs);
    if (unlink(fulink.c_str()) == -1) {
        e2logger_error("Unable to unlink monitor_flag ", fulink, " error: ", strerror(errno));
    }
    return;
}

stat_rec dstat;
stat_rec *dystat = &dstat;

// DECLARATIONS

// Signal handlers
extern "C" {
//void sig_chld(int signo);
//void sig_term(int signo); // This is so we can kill our children
//void sig_termsafe(int signo); // This is so we can kill our children safer
//void sig_hup(int signo); // This is so we know if we should re-read our config.
//void sig_usr1(int signo); // This is so we know if we should re-read our config but not kill current connections
//void sig_childterm(int signo);
//#ifdef ENABLE_SEGV_BACKTRACE
//void sig_segv(int signo, siginfo_t *info, void *secret); // Generate a backtrace on segfault
//#endif
}

// fork off into background
bool daemonise();
// create specified amount of child threads

//void handle_connections(int tindex);  // needs changing to be threadish

// setuid() to proxy user (not just seteuid()) - used by child processes & logger/URL cache for security & resource usage reasons
bool drop_priv_completely();

// IMPLEMENTATION

// signal handlers
extern "C" { // The kernel knows nothing of objects so
// we have to have a lump of c
//void sig_term(int signo)
//{
    //sig_term_killall = true;
    //ttg = true; // its time to go
//}
//void sig_termsafe(int signo)
//{
    //ttg = true; // its time to go
//}
//void sig_hup(int signo)
//{
    //reloadconfig = true;
//#ifdef E2DEBUG
    //std::cerr << "HUP received." << std::endl;
//#endif
//}
//void sig_usr1(int signo)
//{
    //gentlereload = true;
//#ifdef E2DEBUG
    //std::cerr << "USR1 received." << std::endl;
//#endif
//}
//void sig_childterm(int signo)
//{
//#ifdef E2DEBUG
    //std::cerr << "TERM received." << std::endl;
//#endif
    //_exit(0);
//}

#ifdef  NOTDEF
#ifdef ENABLE_SEGV_BACKTRACE
void sig_segv(int signo, siginfo_t *info, void *secret)
{
#ifdef E2DEBUG
    std::cerr << "SEGV received." << std::endl;
#endif
    // Extract "real" info about first stack frame
    ucontext_t *uc = (ucontext_t *)secret;
#ifdef REG_EIP
    e2logger_error("SEGV received: memory address ", info->si_addr, ", EIP ", (void *)(uc->uc_mcontext.gregs[REG_EIP]));
#else
    e2logger_error("SEGV received: memory address ", info->si_addr, ", RIP ", (void *)(uc->uc_mcontext.gregs[REG_RIP]));
#endif
    // Generate backtrace
    void *addresses[20];
    char **strings;
    int c = backtrace(addresses, 20);
// Overwrite call to sigaction with caller's address
// to give a more useful backtrace
#ifdef REG_EIP
    addresses[1] = (void *)(uc->uc_mcontext.gregs[REG_EIP]);
#else
    addresses[1] = (void *)(uc->uc_mcontext.gregs[REG_RIP]);
#endif
    strings = backtrace_symbols(addresses, c);
    printf("backtrace returned: %d\n", c);
    // Skip first stack frame - it points to this signal handler
    for (int i = 1; i < c; i++) {
        e2logger_error(i, " ",  (size_t)addresses[i]);
        e2logger_error(strings[i]);
    }
    // Kill off the current process
    //raise(SIGTERM); // Do we want to do this?
}
#endif
#endif
}

// completely drop our privs - i.e. setuid, not just seteuid
bool drop_priv_completely()
{
    // This is done to solve the problem where the total processes for the
    // uid rather than euid is taken for RLIMIT_NPROC and so can't fork()
    // as many as expected.
    // It is also more secure.
    //
    // Suggested fix by Lawrence Manning Tue 25th February 2003
    //

    int rc = seteuid(o.proc.root_user); // need to be root again to drop properly
    if (rc == -1) {
        e2logger_error("Unable to seteuid(suid)");
        return false; // setuid failed for some reason so exit with error
    }
    rc = setuid(o.proc.proxy_user);
    if (rc == -1) {
        e2logger_error("Unable to setuid()");
        return false; // setuid failed for some reason so exit with error
    }
    return true;
}

// Fork ourselves off into the background
bool daemonise()
{
    if (o.no_daemon) {
        return true;
    }
#ifdef E2DEBUG
    return true; // if debug mode is enabled we don't want to detach
#endif

    if (o.proc.is_daemonised) {
        return true; // we are already daemonised so this must be a
        // reload caused by a HUP
    }

    int nullfd = -1;
    if ((nullfd = open("/dev/null", O_WRONLY, 0)) == -1) {
        e2logger_error("Couldn't open /dev/null");
        return false;
    }

    pid_t pid;
    if ((pid = fork()) < 0) {
        // Error!!
        close(nullfd);
        return false;
    } else if (pid != 0) {
        // parent goes...
        if (nullfd != -1) {
            close(nullfd);
        }
        // bye-bye
        exit(0);
    }

    // child continues
    dup2(nullfd, 0); // stdin
    dup2(nullfd, 1); // stdout
    dup2(nullfd, 2); // stderr
    close(nullfd);

    setsid(); // become session leader
    //int dummy = chdir("/"); // change working directory
    if (chdir("/") != 0) {// change working directory
	    e2logger_error(" Can't change / directory !");
	    return false;
    }
    umask(0); // clear our file mode creation mask
    umask(S_IWGRP | S_IWOTH); // set to mor sensible setting??

    o.proc.is_daemonised = true;

    return true;
}

// *
// *
// *  worker thread code
// *
// *

// handle any connections received by this thread
void handle_connections(int tindex)
{
    thread_id = "hw" + std::to_string(tindex);
    try {
        while (!ttg) {  // extra loop in order to delete and create ConnentionHandler on new lists or error
            ConnectionHandler h;    // the class that handles the connections
	        String ip;

            while (!ttg) {
                e2logger_debugnet(" waiting connection on http_worker_Q ");
                LQ_rec rec = o.http_worker_Q.pop();
                Socket *peersock = rec.sock;
                e2logger_debugnet(" popped connection from http_worker_Q");
                if (ttg) break;

                String peersockip = peersock->getPeerIP();
                if (peersock->getFD() < 0 || peersockip.length() < 7) {
//            if (o.logconerror)
                    e2logger_info("Error accepting. (Ignorable)");
                    continue;
                }
                ++dystat->busychildren;
                ++dystat->conx;

                int rc = h.handlePeer(*peersock, peersockip, dystat, rec.ct_type); // deal with the connection
                e2logger_debugnet("handle_peer returned: ", String(rc));

                --dystat->busychildren;
                delete peersock;
                break;
            };
        };
    } catch (...) {
        e2logger_error("worker thread caught unexpected exception - exiting");
    }
}


// *
// *
// * end of worker thread code
// *
// *

void tell_monitor(bool active) //may not be needed
{

    String buff(o.monitor_helper);
    String buff1;

    if (active)
        buff1 = " start";
    else
        buff1 = " stop";

    e2logger_error("Monitorhelper called: ", buff, buff1);
    pid_t childid;
    childid = fork();

    if (childid == -1) {
        e2logger_error("Unable to fork to tell monitorhelper error: ", strerror(errno));
        return;
    };

    if (childid == 0) { // Am the child
	    int rc = seteuid(o.proc.root_user);
    	if (rc != -1) {
            int systemreturn = execl(buff.c_str(), buff.c_str(), buff1.c_str(), (char *)NULL); // should not return from call
            if (systemreturn == -1) {
                e2logger_error("Unable to exec: ",buff, buff1, " : errno ",  errno, " ", strerror(errno));
                exit(0);
            }
        } else {
            	e2logger_error("Unable to set uid root");
            	exit(0);
	    }
    };

    if (childid > 0) { // Am the parent
        int rc;
        int status;
        rc = waitpid(childid, &status, 0);
        if (rc == -1) {
            e2logger_error("Wait for monitorhelper returned : errno ", strerror(errno));
            return;
        };
        if (WIFEXITED(status)) {
            return;
        } else {
            e2logger_error("Monitorhelper exited abnormally");
            return;
        };
    };
};

#ifdef NOTDEF
void wait_for_proxy()
{
    Socket proxysock;
    int rc;

    try {
        // ...connect to proxy
        rc = proxysock.connect(o.proxy_ip, o.proxy_port);
        if (!rc) {
            proxysock.close();
            //cache_erroring = 0;
            return;
        }
        if (errno == EINTR) {
            return;
        }
    } catch (std::exception &e) {
        e2logger_debug(" -exception while creating proxysock: ", e.what());
    }
    e2logger_error("Proxy is not responding - Waiting for proxy to respond");
    if (o.monitor_flag_flag)
        monitor_flag_set(false);
    if (o.monitor_helper_flag)
        tell_monitor(false);
    int wait_time = 1;
    //int report_interval = 600; // report every 10 mins to log
    int cnt_down = o.proxy_failure_log_interval;
    while (true) {
        rc = proxysock.connect(o.proxy_ip, o.proxy_port);
        if (!rc) {
            proxysock.close();
            //cache_erroring = 0;
            e2logger_error("Proxy now responding - resuming after %d seconds", wait_time);
            if (o.monitor_flag_flag)
               monitor_flag_set(true);
            if (o.monitor_helper_flag)
               tell_monitor(true);
            return;
        } else {
            if (ttg)
                return;
            wait_time++;
            cnt_down--;
            if (cnt_down < 1) {
                e2logger_error("Proxy not responding - still waiting after %d seconds", wait_time);
                cnt_down = o.proxy_failure_log_interval;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
}
#endif


// *
// *
// * logger, IP list and URL cache main loops
// *
// *


void accept_connections(int index) // thread to listen on a single listening socket
{
    try {
        unsigned int ct_type = serversockets.getType(index);
        int errorcount = 0;
        thread_id = "listen_";
        thread_id += std::to_string(index);
        thread_id += "_";
        switch(ct_type) {
            case CT_PROXY:
                thread_id += "proxy: ";
                break;
            case CT_ICAP:
                thread_id += "icap: ";
                break;
            case CT_THTTPS:
                thread_id += "thttps: ";
                break;

        }
        thread_id += std::to_string(ct_type);
        thread_id += ": ";
        while ((errorcount < 30) && !ttg) {
            Socket *peersock = serversockets[index]->accept();
            int err = serversockets[index]->getErrno();
            if (err == 0 && peersock != NULL && peersock->getFD() > -1) {
            	if (ttg) {
			        delete peersock;
			        break;
		        }
                e2logger_debug("got connection from accept");

                if (peersock->getFD() > dstat.maxusedfd) dstat.maxusedfd = peersock->getFD();
                errorcount = 0;
                LQ_rec rec;
                rec.sock = peersock;
                rec.ct_type = ct_type;
                o.http_worker_Q.push(rec);

                e2logger_debug("pushed connection to http_worker_Q");
            } else {
            	if (ttg) {
			        if (peersock != nullptr) delete peersock;
			        break;
		        }
                e2logger_error("Error on accept: errorcount ", String(errorcount), " errno: ", String(err));

                ++errorcount;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        };
        if (!ttg) 
            e2logger_error("Error count on accept exceeds 30");
        serversockets[index]->close();
    } catch (...) {
       e2logger_error("listener thread caught unexpected exception exiting");
    }
    if (o.logconerror) {
        e2logger_info("listener thread exiting");
    }
}

// *
// *
// * end logger, IP list and URL cache code
// *
// *

// Does lots and lots of things - creates url cache & logger threads, creates child threads for connection handling, does tidying up on exit
// also handles the various signalling options e2g supports (reload config, flush cache, kill all processes etc.)
int fc_controlit()   //
{
    int rc;
    bool is_starting = true;
    ttg = false;
    //e2logger_ttg = false;
    reloadconfig = false;
    gentlereload = false;
    reload_cnt = 0;

    o.lm.garbageCollect();
    thread_id = "master: ";

    // allocate & create our server sockets
    if (o.map_ports_to_ips) {
        serversocketcount = o.filter_ip.size();
    } else {
        if (o.filter_ip.size() > 0) {
            serversocketcount = o.filter_ip.size() * o.filter_ports.size();
        } else {
            serversocketcount = o.filter_ports.size();
        }
    }

    int serversocktopproxy = serversocketcount;

    if (o.transparenthttps_port > 0)
        ++serversocketcount;
    if (o.icap_port> 0)
        ++serversocketcount;

    serversockets.reset(serversocketcount);
    int *serversockfds = serversockets.getFDAll();
    //std::thread *listen_treads[serversocketcount];
    for (int i = 0; i < serversocketcount; i++) {
        // if the socket fd is not +ve then the socket creation failed
        if (serversockfds[i] < 0) {
            e2logger_error("Error creating server socket ", String(i));
            delete[] serversockfds;
            return 1;
        }
    }

// PRA 10-10-2005
/*bool needdrop = false;

	if (o.filter_port < 1024) */
#ifdef E2DEBUG
    std::cerr << thread_id << "seteuiding for low port binding/pidfile creation" << std::endl;
#endif
//needdrop = true;
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t)-1, o.proc.root_user);
#else
    rc = seteuid(o.proc.root_user);
#endif
    if (rc == -1) {
        e2logger_error("Unable to seteuid() to bind filter port.");
        delete[] serversockfds;
        return 1;
    }

    // we have to open/create as root before drop privs
    int pidfilefd = sysv_openpidfile(o.pid_filename);
    if (pidfilefd < 0) {
        e2logger_error("Error creating/opening pid file: ", o.pid_filename);
        delete[] serversockfds;
        return 1;
    }

    // we expect to find a valid filter ip 0 specified in conf if multiple IPs are in use.
    // if we don't find one, bind to any, as per old behaviour.
    // XXX AAAARGH!
    if (o.filter_ip[0].length() > 6) {
        if (serversockets.bindAll(o.filter_ip, o.filter_ports)) {
            e2logger_error("Error binding server socket (is something else running on the filter port and ip?");
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    } else {
        // listen/bind to a port (or ports) on any interface
        if (o.map_ports_to_ips) {
            if (serversockets.bindSingle(o.filter_port)) {
                e2logger_error("Error binding server socket: [", o.filter_port, "] (", strerror(errno), ")" );
                close(pidfilefd);
                delete[] serversockfds;
                return 1;
            }
        } else {
            if (serversockets.bindSingleM(o.filter_ports)) {
                e2logger_error("Error binding server sockets: (", strerror(errno), ")" );
                close(pidfilefd);
                delete[] serversockfds;
                return 1;
            }
        }
    }

    if (o.transparenthttps_port > 0) {
        if (serversockets.bindSingle(serversocktopproxy++,o.transparenthttps_port, CT_THTTPS)) {
            e2logger_error("Error binding server thttps socket: (", strerror(errno), ")");
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    };

    if (o.icap_port > 0) {
        if (serversockets.bindSingle(serversocktopproxy,o.icap_port, CT_ICAP)) {
            e2logger_error("Error binding server icap socket: (", strerror(errno), ")" );
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    };

// Made unconditional for same reasons as above
//if (needdrop)
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t)-1, o.proc.proxy_user);
#else
    rc = seteuid(o.proc.proxy_user); // become low priv again
#endif
    if (rc == -1) {
        e2logger_error("%sUnable to re-seteuid()");
        close(pidfilefd);
        delete[] serversockfds;
        return 1; // seteuid failed for some reason so exit with error
    }

    if (serversockets.listenAll(256)) { // set it to listen mode with a kernel
        // queue of 256 backlog connections
        e2logger_error("Error listening to server socket");
        close(pidfilefd);
        delete[] serversockfds;
        return 1;
    }

    if (!daemonise()) {
        // detached daemon
        e2logger_error("Error daemonising");
        close(pidfilefd);
        delete[] serversockfds;
        return 1;
    }

    //init open ssl
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    if (o.use_openssl_conf) {
    	if(o.have_openssl_conf) {
            if (CONF_modules_load_file(o.openssl_conf_path.c_str(), nullptr,0) != 1) {
                e2logger_error("Error reading openssl config file ", o.openssl_conf_path.c_str());
                return false;
            }
    	} else {
            if (CONF_modules_load_file(nullptr, nullptr,0) != 1) {
                e2logger_error("Error reading default openssl config files");
                return false;
            }
    	}
    }
    SSL_library_init();

    // this has to be done after daemonise to ensure we get the correct PID.
    rc = sysv_writepidfile(pidfilefd); // also closes the fd
    if (rc != 0) {
        e2logger_error("Error writing to the e2guardian.pid file: ", strerror(errno));
        delete[] serversockfds;
        return false;
    }
    // We are now a daemon so all errors need to go in the syslog, rather
    // than being reported on screen as we've detached from the console and
    // trying to write to stdout will not be nice.

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    // Now start creating threads so main thread can just handle signals, list reloads and stats
    // This removes need for select and/or epoll greatly simplifying the code
    // Threads are created for logger, a separate thread for each listening port
    // and an array of worker threads to deal with the work.
    //if (!o.no_logger) {
    if (e2logger.isEnabled(LoggerSource::access)) {
        std::thread log_thread(AccessLogger::log_listener, std::ref(o.log.log_Q), false );
        log_thread.detach();
        e2logger_trace("log_listener thread created");
    }

    //if(o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::debugrequest)) {
        std::thread RQlog_thread(AccessLogger::log_listener, std::ref(o.log.RQlog_Q), true );
        RQlog_thread.detach();
        e2logger_trace("RQlog_listener thread created");
    }

    // I am the main thread here onwards.
    e2logger_trace("Master thread created threads");

    sigset_t signal_set;
    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGPIPE);
    sigaddset(&signal_set, SIGTERM);
    sigaddset(&signal_set, SIGUSR1);

#ifdef __OpenBSD__
    // OpenBSD does not support posix sig_timed_wait, so have to use timer and SIGALRM 
    // set up timer for main loop
    struct itimerval timeout;
    timeout.it_interval.tv_sec = 0;
    timeout.it_interval.tv_usec = (suseconds_t) 0;
    timeout.it_value.tv_usec = (suseconds_t) 0;
    sigaddset(&signal_set, SIGALRM);
#else
    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = (long) 0;
#endif
    int stat;
    stat = pthread_sigmask(SIG_BLOCK, &signal_set, NULL);
    if (stat != 0) {
        e2logger_error("Error setting sigmask");
        return 1;
    }

    e2logger_trace("sig handlers done");

    dystat->busychildren = 0; // to keep count of our children

    // worker thread generation
    std::vector <std::thread> http_wt;
    http_wt.reserve(o.http_workers);

    int i;
    for (i = 0; i < o.http_workers; i++) {
        http_wt.push_back(std::thread(handle_connections, i));
    }
    for (auto &i : http_wt) {
        i.detach();
   }

   e2logger_trace("http_worker threads created");

    //   set listener threads going
    std::vector <std::thread> listen_threads;
    listen_threads.reserve(serversocketcount);
    for (int i = 0; i < serversocketcount; i++) {
        listen_threads.push_back(std::thread(accept_connections, i));
    }
    for (auto &i : listen_threads) {
        i.detach();
    }

    e2logger_trace("listen  threads created");

    time_t tmaxspare;

    time(&tmaxspare);

    failurecount = 0; // as we don't exit on an error with select()
    // due to the fact that these errors do happen
    // every so often on a fully working, but busy
    // system, we just watch for too many errors
    // consecutivly.

    is_starting = true;

    if (reloadconfig) {
        e2logger_info("Reconfiguring E2guardian: done");
    } else {
        e2logger_info("Started successfully.");
        dystat->start();
    }
    reloadconfig = false;

    if (is_starting) {
        if (o.monitor_flag_flag)
            monitor_flag_set(true);
    	if (o.monitor_helper_flag){
        	tell_monitor(true);
        }
        is_starting = false;
   }

    while (failurecount < 30 && !ttg && !reloadconfig) {

        // loop, essentially, for ever until 30
        // consecutive errors in which case something
        // is badly wrong.
        // OR, its timetogo - got a sigterm
        // OR, we need to exit to reread config
        if (gentlereload) {
            e2logger_trace("gentle reload activated");

            e2logger_info("Reconfiguring E2guardian: gentle reload starting");
            if (o.createLists(++reload_cnt))
                e2logger_info("Reconfiguring E2guardian: gentle reload completed");
            else
                e2logger_info("%sReconfiguring E2guardian: gentle reload failed");

            gentlereload = false;
            continue;        //  OK to continue even if gentle failed - just continue to use previous lists
        }
#ifdef __OpenBSD__
    // OpenBSD does not support posix sig_timed_wait, so have to use timer and SIGALRM 
        timeout.it_value.tv_sec = 5;
        setitimer(ITIMER_REAL, &timeout, NULL);
        int rsig;
        rc = sigwait(&signal_set, &rsig);
        if (rc < 0) {
            if (errno != EAGAIN) {
                e2logger_info("Unexpected error from sigtimedwait(): ", String(errno), " ", strerror(errno));
            }
        } else {
            if (rsig == SIGUSR1)
                gentlereload = true;
            if (rsig == SIGTERM)
                ttg = true;
            if (rsig == SIGHUP)
                gentlereload = true;
            if (rsig != SIGALRM) {
                // unset alarm
                timeout.it_value.tv_sec = 0;
                //timer_settime(timerid,0,&timeout, NULL);
                setitimer(ITIMER_REAL, &timeout, NULL);

                e2logger_debug("signal:", String(rc);
                if (o.logconerror) {
                    e2logger_info("sigtimedwait() signal recd:", String(rsig) );
                }
            }
        }
#else
	// other posix compliant platforms
        timeout.tv_sec = 5;
        rc = sigtimedwait(&signal_set, NULL, &timeout);
        if (rc < 0) {
            if (errno != EAGAIN) {
                e2logger_info("Unexpected error from sigtimedwait():", String(errno), " ", strerror(errno));
            }
        } else {
            if (rc == SIGUSR1)
                gentlereload = true;
            if (rc == SIGTERM)
                ttg = true;
            if (rc == SIGHUP)
                gentlereload = true;

            e2logger_debug("signal: ", String(rc));
            if (o.logconerror) {
                e2logger_info("ssigtimedwait() signal recd:", String(rc));
            }
        }
#endif   // end __OpenBSD__ else

        int q_size = o.http_worker_Q.size();
        e2logger_debug("busychildren:", String(dystat->busychildren),
                    " worker Q size:", String(q_size) );
        if( o.dstat_log_flag) {
            if (q_size > 10) {
                e2logger_info("Warning: all ", String(o.http_workers), " http_worker threads are busy and ", String(q_size), " connections are waiting in the queue.");
            }
        } else {
            int busy_child = dystat->busychildren;
            if (busy_child > (o.http_workers - 10))
                e2logger_info("Warning system is full : max httpworkers: ", String(o.http_workers), " Used: ", String(busy_child));
        }

        //      if (is_starting)

        time_t now = time(NULL);


        if (o.dstat_log_flag && (now >= dystat->end_int))
            dystat->reset();
    }


    //  tidy-up

    sigfillset(&signal_set);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

    e2logger_info("Stopping");

    if (o.monitor_flag_flag)
       monitor_flag_set(false);
    if (o.monitor_helper_flag)
        tell_monitor(false); // tell monitor that we are not accepting any more connections

    if (o.logconerror) {
        e2logger_info("sending null socket to http_workers to stop them");
    }
    Socket* NS = NULL;
    LQ_rec rec;
    rec.sock = NS;
    rec.ct_type = CT_PROXY;
    for (i = 0; i < o.http_workers; i++) {
        o.http_worker_Q.push(rec);
    }
   // dystat->reset();    // remove this line for production version

    //std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    //e2logger_info("2nd wait complete");
    // e2logger_ttg = true;    
    AccessLogger::shutDown();
    AccessLogger::LogRecord null_record;
    o.log.log_Q.push(null_record);
    //if (o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::debugrequest)) {        
        o.log.RQlog_Q.push(null_record);
    }

    if (o.logconerror) {
        e2logger_info("stopping any remaining connections");
    }
    serversockets.self_connect();   // stop accepting connections
    if (o.logconerror) {
        e2logger_info("connections stopped");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    if (o.dstat_log_flag) dystat->close();

    delete[] serversockfds;

    if (o.logconerror) {
        e2logger_info("Main thread exiting.");
    }
    return 0;
}
