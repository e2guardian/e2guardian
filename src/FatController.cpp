// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include <sstream>
#include <cstdlib>
#include <syslog.h>
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

#ifdef __SSLMITM
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#endif //__SSLMITM

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
std::atomic<bool> logger_ttg;
std::atomic<bool> gentlereload;
//static volatile bool sig_term_killall = false;
std::atomic<bool> reloadconfig ;
std::atomic<int> reload_cnt;

extern OptionContainer o;
extern bool is_daemonised;
extern thread_local std::string thread_id;

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
           syslog(LOG_ERR, "Unable to open dstats_log %s for writing\nContinuing without logging\n",
           o.dstat_location.c_str());
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
        bc, o.http_worker_Q.size(), o.log_Q->size(), cnx, cps, rqx, rqs, mfd, LC);
    } else {
        fprintf(fs, "%ld	%d	%d	%d	%d	%ld	%ld	%ld	%ld	%d	%d\n", now, o.http_workers,
        bc, o.http_worker_Q.size(), o.log_Q->size(), cnx, cps, rqx, rqs, mfd, LC);
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

#ifdef __SSLMITM
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static pthread_mutex_t  *ssl_lock_array;

static void ssl_lock_callback(int mode, int type, char *file, int line)
{
  (void)file;
  (void)line;
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(ssl_lock_array[type]));
  }
  else {
    pthread_mutex_unlock(&(ssl_lock_array[type]));
  }
}

static void init_ssl_locks(void)
{
  int i;

  ssl_lock_array=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                        sizeof(pthread_mutex_t));
  for (i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(ssl_lock_array[i]),NULL);
  }

  //CRYPTO_set_id_callback((unsigned long (*)())thread_id);
  CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))ssl_lock_callback);
}

static void kill_ssl_locks(void)
{
  int i;

  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(ssl_lock_array[i]));

  OPENSSL_free(ssl_lock_array);
}
#endif
#endif   //end __SSLMITM

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
        syslog(LOG_ERR, "Unable to open monitor_flag %s for writing\n",
            ftouch.c_str());
        o.monitor_flag_flag = false;
    }
    fclose(fs);
    if (unlink(fulink.c_str()) == -1) {
        syslog(LOG_ERR, "Unable to unlink monitor_flag %s error: %s", fulink.c_str(), strerror(errno));
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

// logging & URL cache processes
void log_listener(std::string log_location, bool is_RQlog, bool logsyslog, Queue<std::string>* log_Q);

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
    syslog(LOG_ERR, "SEGV received: memory address %p, EIP %p", info->si_addr, (void *)(uc->uc_mcontext.gregs[REG_EIP]));
#else
    syslog(LOG_ERR, "SEGV received: memory address %p, RIP %p", info->si_addr, (void *)(uc->uc_mcontext.gregs[REG_RIP]));
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
        syslog(LOG_ERR, "%d: %zX ", i, (size_t)addresses[i]);
        syslog(LOG_ERR, "%s", strings[i]);
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

    int rc = seteuid(o.root_user); // need to be root again to drop properly
    if (rc == -1) {
        syslog(LOG_ERR, "%s%s", thread_id.c_str(), "Unable to seteuid(suid)");
#ifdef E2DEBUG
        std::cerr << thread_id << strerror(errno) << std::endl;
#endif
        return false; // setuid failed for some reason so exit with error
    }
    rc = setuid(o.proxy_user);
    if (rc == -1) {
        syslog(LOG_ERR, "%s%s", thread_id.c_str(), "Unable to setuid()");
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

    if (is_daemonised) {
        return true; // we are already daemonised so this must be a
        // reload caused by a HUP
    }

    int nullfd = -1;
    if ((nullfd = open("/dev/null", O_WRONLY, 0)) == -1) {
        syslog(LOG_ERR, "%s%s", thread_id.c_str(), "Couldn't open /dev/null");
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
	std::cerr << thread_id << " Can't change / directory !"  << std::endl;
	return false;
    }
    umask(0); // clear our file mode creation mask
    umask(S_IWGRP | S_IWOTH); // set to mor sensible setting??

    is_daemonised = true;

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
    thread_id = "hw";
    thread_id += std::to_string(tindex);
    thread_id += ": ";
    try {
        while (!ttg) {  // extra loop in order to delete and create ConnentionHandler on new lists or error
            ConnectionHandler h;
            // the class that handles the connections
	    //int rc = 0;
	    String ip;
#ifdef E2DEBUG
            std::cerr << thread_id << " in  handle connection"  << std::endl;
#endif
//            std::thread::id this_id = std::this_thread::get_id();
            //reloadconfig = false;
            while (!ttg) {
#ifdef E2DEBUG
                std::cerr << thread_id << " waiting connection on http_worker_Q "  << std::endl;
#endif
                LQ_rec rec = o.http_worker_Q.pop();
                Socket *peersock = rec.sock;
#ifdef E2DEBUG
                std::cerr << thread_id << " popped connection from http_worker_Q"  << std::endl;
#endif
                if (ttg) break;

                String peersockip = peersock->getPeerIP();
                if (peersock->getFD() < 0 || peersockip.length() < 7) {
//            if (o.logconerror)
                    syslog(LOG_INFO, "%sError accepting. (Ignorable)", thread_id.c_str());
                    continue;
                }
                ++dystat->busychildren;
                ++dystat->conx;

#ifdef E2DEBUG
                int rc = h.handlePeer(*peersock, peersockip, dystat, rec.ct_type); // deal with the connection
                std::cerr << thread_id << "handle_peer returned: " << rc << std::endl;
#else
                h.handlePeer(*peersock, peersockip, dystat, rec.ct_type); // deal with the connection
#endif
                --dystat->busychildren;
                delete peersock;
                break;
            };
        };
    } catch (...) {
        syslog(LOG_ERR,"%sworker thread caught unexpected exception - exiting", thread_id.c_str());
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

    syslog(LOG_ERR, "%sMonitorhelper called: %s%s", thread_id.c_str(), buff.c_str(), buff1.c_str());
    pid_t childid;
    childid = fork();

    if (childid == -1) {
        syslog(LOG_ERR, "%sUnable to fork to tell monitorhelper error: %s", thread_id.c_str(), strerror(errno));
        return;
    };

    if (childid == 0) { // Am the child
	int rc = seteuid(o.root_user);
	if (rc != -1) {
       		int systemreturn = execl(buff.c_str(), buff.c_str(), buff1.c_str(), (char *)NULL); // should not return from call
		if (systemreturn == -1) {
            		syslog(LOG_ERR, "Unable to exec: %s%s : errno %d %s", buff.c_str(), buff1.c_str(), errno, strerror(errno));
            		exit(0);
		}
        } else {
            	syslog(LOG_ERR, "Unable to set uid root");
            	exit(0);
	}
    };

    if (childid > 0) { // Am the parent
        int rc;
        int status;
        rc = waitpid(childid, &status, 0);
        if (rc == -1) {
            syslog(LOG_ERR, "%sWait for monitorhelper returned : errno %s", thread_id.c_str(), strerror(errno));
            return;
        };
        if (WIFEXITED(status)) {
            return;
        } else {
            syslog(LOG_ERR, "%sMonitorhelper exited abnormally", thread_id.c_str());
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
#ifdef E2DEBUG
        std::cerr << thread_id << " -exception while creating proxysock: " << e.what() << std::endl;
#endif
    }
    syslog(LOG_ERR, "Proxy is not responding - Waiting for proxy to respond");
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
            syslog(LOG_ERR, "Proxy now responding - resuming after %d seconds", wait_time);
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
                syslog(LOG_ERR, "Proxy not responding - still waiting after %d seconds", wait_time);
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

void log_listener(std::string log_location, bool is_RQlog, bool logsyslog, Queue<std::string> *log_Q) {
    if (is_RQlog)
        thread_id = "RQlog: ";
    else
        thread_id = "log: ";
    try {
#ifdef E2DEBUG
    std::cerr << thread_id << "log listener started" << std::endl;
#endif

#ifdef ENABLE_EMAIL
    // Email notification patch by J. Gauthier
    std::map<std::string, int> violation_map;
    std::map<std::string, int> timestamp_map;
    std::map<std::string, std::string> vbody_map;

    int curv_tmp, stamp_tmp, byuser;
#endif

    //String where, what, how;
    std::string cr("\n");

    std::string where, what, how, cat, clienthost, from, who, mimetype, useragent, ssize, sweight, params, message_no;
    std::string stype, postdata, flags, searchterms;
    int port = 80, isnaughty = 0, isexception = 0, code = 200, naughtytype = 0;
    int cachehit = 0, wasinfected = 0, wasscanned = 0, filtergroup = 0;
    long tv_sec = 0, tv_usec = 0, endtv_sec = 0, endtv_usec = 0;
    int contentmodified = 0, urlmodified = 0, headermodified = 0;
    int headeradded = 0;

    std::ofstream *logfile = NULL;
    if (!logsyslog) {
        logfile = new std::ofstream(log_location.c_str(), std::ios::app);
        if (logfile->fail()) {
            syslog(LOG_ERR, "%sError opening/creating log file.", thread_id.c_str());
#ifdef E2DEBUG
            std::cerr << thread_id << "Error opening/creating log file: " << log_location << std::endl;
#endif
            delete logfile;
            return; // return with error
        }
    }

    String server("");
    // Get server name - only needed for formats 5 & 7
    if ((o.log_file_format == 5) || (o.log_file_format == 7)) {
    	server = o.server_name;
    }

    std::string exception_word = o.language_list.getTranslation(51);
    exception_word = "*" + exception_word + "* ";
    std::string denied_word = o.language_list.getTranslation(52);
    denied_word = "*" + denied_word;
    std::string infected_word = o.language_list.getTranslation(53);
    infected_word = "*" + infected_word + "* ";
    std::string scanned_word = o.language_list.getTranslation(54);
    scanned_word = "*" + scanned_word + "* ";
    std::string contentmod_word = o.language_list.getTranslation(55);
    contentmod_word = "*" + contentmod_word + "* ";
    std::string urlmod_word = o.language_list.getTranslation(56);
    urlmod_word = "*" + urlmod_word + "* ";
    std::string headermod_word = o.language_list.getTranslation(57);
    headermod_word = "*" + headermod_word + "* ";
    std::string headeradd_word = o.language_list.getTranslation(58);
    headeradd_word = "*" + headeradd_word + "* ";
    std::string neterr_word = o.language_list.getTranslation(59);
    neterr_word = "*" + neterr_word + "* ";
    std::string blank_str;

    if(o.use_dash_for_blanks)
        blank_str = "-";
    else
        blank_str = "";


    while (!logger_ttg) { // loop, essentially, for ever
        std::string loglines;
        loglines.append(log_Q->pop());  // get logdata from queue
        if (logger_ttg) break;
#ifdef E2DEBUG
            std::cerr << thread_id << "received a log request" <<  loglines << std::endl;
#endif

        // Formatting code migration from ConnectionHandler
        // and email notification code based on patch provided
        // by J. Gauthier

        // read in the various parts of the log string
        bool error = true;
        int itemcount = 0;
        //char * dup = strdup(loglines.c_str());
        //const char *delim = "\n";
        std::istringstream iss(loglines);
        std::string logline;
        std::shared_ptr<LOptionContainer> ldl;
        ldl = o.currentLists();

        while (std::getline(iss, logline)) {
            // Loop around reading in data, because we might have huge URLs
            std::string s;

            if (o.use_dash_for_blanks && logline == "") {
                s = "-";
            } else if (!o.use_dash_for_blanks && logline == "-") {
                s = "";
            } else {
                s = logline;
            }

            switch (itemcount) {
                case 0:
                    isexception = atoi(logline.c_str());
                    break;
                case 1:
                    cat = s;
                    break;
                case 2:
                    isnaughty = atoi(logline.c_str());
                    break;
                case 3:
                    naughtytype = atoi(logline.c_str());
                    break;
                case 4:
                    sweight = s;
                    break;
                case 5:
                    where = s;
                    break;
                case 6:
                    what = s;
                    break;
                case 7:
                    how = s;
                    break;
                case 8:
                    who = s;
                    break;
                case 9:
                    from = s;
                    break;
                case 10:
                    port = atoi(logline.c_str());
                    break;
                case 11:
                    wasscanned = atoi(logline.c_str());
                    break;
                case 12:
                    wasinfected = atoi(logline.c_str());
                    break;
                case 13:
                    contentmodified = atoi(logline.c_str());
                    break;
                case 14:
                    urlmodified = atoi(logline.c_str());
                    break;
                case 15:
                    headermodified = atoi(logline.c_str());
                    break;
                case 16:
                    ssize = s;
                    break;
                case 17:
                    filtergroup = atoi(logline.c_str());
                    if (filtergroup < 0 || filtergroup > o.numfg) filtergroup = 0;
                    break;
                case 18:
                    code = atoi(logline.c_str());
                    break;
                case 19:
                    cachehit = atoi(logline.c_str());
                    break;
                case 20:
                    mimetype = s;
                    break;
                case 21:
                    tv_sec = atol(logline.c_str());
                    break;
                case 22:
                    tv_usec = atol(logline.c_str());
                    break;
                case 23:
                    endtv_sec = atol(logline.c_str());
                    break;
                case 24:
                    endtv_usec = atol(logline.c_str());
                    break;
                case 25:
                    clienthost = s;
                    break;
                case 26:
                    useragent = s;
                    break;
                case 27:
                    params = s;
                    break;
                case 28:
                    postdata = s;
                    break;
                case 29:
                    message_no = s;
                    break;
                case 30:
                    headeradded = atoi(logline.c_str());
                    break;
                case 31:
                    flags = s;
                    break;
                case 32:
                    searchterms = s;
                    error = false;
                    break;
            }
            itemcount++;
        }


        // don't build the log line if we couldn't read all the component parts
        if (error)
            continue;

        // Start building the log line

        if (port != 0 && port != 80) {
            // put port numbers of non-standard HTTP requests into the logged URL
            String newwhere(where);
            if (newwhere.after("://").contains("/")) {
                String proto, host, path;
                proto = newwhere.before("://");
                host = newwhere.after("://");
                path = host.after("/");
                host = host.before("/");
                newwhere = proto;
                newwhere += "://";
                newwhere += host;
                newwhere += ":";
                newwhere += String((int) port);
                newwhere += "/";
                newwhere += path;
                where = newwhere;
            } else {
                where += ":";
                where += String((int) port);
            }
        }

        bool neterr = false;

        // stamp log entries so they stand out/can be searched
        switch (naughtytype) {
            case 1:
                stype = "-POST";
                break;
            case 2:
                stype = "-PARAMS";
                break;
            case 3:
                neterr = true;
                break;
            default:
                stype.clear();
        }

        if (isnaughty) {
            if (neterr)
                what = neterr_word + what;
            else
                what = denied_word + stype + "* " + what;
        } else if (isexception && (o.log_exception_hits == 2)) {
            what = exception_word + what;
        }

        if (wasinfected)
            what = infected_word + stype + "* " + what;
        else if (wasscanned)
            what = scanned_word + what;

        if (contentmodified) {
            what = contentmod_word + what;
        }
        if (urlmodified) {
            what = urlmod_word + what;
        }
        if (headermodified) {
            what = headermod_word + what;
        }
        if (headeradded) {
            what = headeradd_word + what;
        }

        std::string builtline, year, month, day, hour, min, sec, when, vbody, utime;

        // create a string representation of UNIX timestamp if desired
        if (o.log_timestamp || (o.log_file_format == 3)
            || (o.log_file_format > 4)) {
            String temp((int) (endtv_usec / 1000));
            while (temp.length() < 3) {
                temp = "0" + temp;
            }
            if (temp.length() > 3) {
                temp = "999";
            }
            utime = temp;
            utime = "." + utime;
            utime = String((int) endtv_sec) + utime;
        }


        if ((o.log_file_format <= 2) || (o.log_file_format == 4)) {
            // "when" not used in format 3, and not if logging timestamps instead in formats 5-8
            //time_t now = time(NULL);
            time_t now = endtv_sec;
            char date[32];
            struct tm *tm = localtime(&now);
            strftime(date, sizeof date, "%Y.%m.%d %H:%M:%S", tm);
            when = date;
            // append timestamp if desired
            if (o.log_timestamp)
                when += " " + utime;
        }

        // blank out IP, hostname and username if desired
        if (o.anonymise_logs) {
            who = "";
            from = "0.0.0.0";
            clienthost.clear();
        } else if ((clienthost == blank_str) || (clienthost == "DNSERROR")) {
            clienthost = from;
        }

        String groupname;
        String stringcode(code);
        String stringgroup(filtergroup + 1);

        if (is_RQlog) {
            groupname = "";
        } else {
            if (stringcode == "407") {
                groupname = "negotiate_identification";
            } else {
                groupname = ldl->fg[filtergroup]->name;
            }
        }

        switch (o.log_file_format) {
            case 4:
                builtline = when + "\t" + who + "\t" + from + "\t" + where + "\t" + what + "\t" + how
                            + "\t" + ssize + "\t" + sweight + "\t" + cat + "\t" + stringgroup + "\t"
                            + stringcode + "\t" + mimetype + "\t" + clienthost + "\t" + groupname
                            #ifdef SG_LOGFORMAT
                            + "\t" + useragent + "\t\t" + o.logid_1 + "\t" + o.prod_id + "\t"
                    + params + "\t" + o.logid_2 + "\t" + postdata;
                            #else
                            + "\t" + useragent + "\t" + params + "\t" + o.logid_1 + "\t" + o.logid_2 + "\t" + postdata;
#endif
                break;
            case 3: {
                // as certain bits of info are logged in format 3, their creation is best done here, not in all cases.
                std::string duration, hier, hitmiss;
                long durationsecs, durationusecs;
                durationsecs = (endtv_sec - tv_sec);
                durationusecs = endtv_usec - tv_usec;
                durationusecs = (durationusecs / 1000) + durationsecs * 1000;
                String temp((int) durationusecs);
                while (temp.length() < 6) {
                    temp = " " + temp;
                }
                duration = temp;

                if (code == 403) {
                    hitmiss = "TCP_DENIED/403";
                } else {
                    if (cachehit) {
                        hitmiss = "TCP_HIT/";
                        hitmiss.append(stringcode);
                    } else {
                        hitmiss = "TCP_MISS/";
                        hitmiss.append(stringcode);
                    }
                }
                hier = "DEFAULT_PARENT/";
                hier += o.proxy_ip;
                builtline =
                        utime + " " + duration + " " + ((clienthost.length() > 0) ? clienthost : from) + " " + hitmiss +
                        " " + ssize + " "
                        + how + " " + where + " " + who + " " + hier + " " + mimetype;
                break;
            }
            case 2:
                builtline = "\"" + when + "\",\"" + who + "\",\"" + from + "\",\"" + where + "\",\"" + what + "\",\""
                            + how + "\",\"" + ssize + "\",\"" + sweight + "\",\"" + cat + "\",\"" + stringgroup +
                            "\",\""
                            + stringcode + "\",\"" + mimetype + "\",\"" + clienthost + "\",\"" +
                            groupname + "\",\""
                            + useragent + "\",\"" + params + "\",\"" + o.logid_1 + "\",\"" + o.logid_2 + "\",\"" +
                            postdata + "\"";
                break;
            case 1:
                builtline = when + " " + who + " " + from + " " + where + " " + what + " "
                            + how + " " + ssize + " " + sweight + " " + cat + " " + stringgroup + " "
                            + stringcode + " " + mimetype + " " + clienthost + " " + groupname + " "
                            + useragent + " " + params + " " + o.logid_1 + " " + o.logid_2 + " " + postdata;
                break;
            case 5:
            case 6:
            case 7:
            case 8:
            default:
                std::string duration;
                long durationsecs, durationusecs;
                durationsecs = (endtv_sec - tv_sec);
                durationusecs = endtv_usec - tv_usec;
                durationusecs = (durationusecs / 1000) + durationsecs * 1000;
                String temp((int) durationusecs);
                duration = temp;

                builtline = utime + "\t"
                            + server + "\t"
                            + who + "\t";
                if (o.log_client_host_and_ip) {
                    builtline += from + "\t";
                    builtline += clienthost + "\t";
                } else {
                    if (clienthost.length() > 2)
                        builtline += clienthost + "\t";
                    else
                        builtline += from + "\t";
                }
                builtline += where + "\t"
                            + how + "\t"
                            + stringcode + "\t"
                            + ssize + "\t"
                            + mimetype + "\t"
                            + (o.log_user_agent ? useragent : blank_str) + "\t"
                            + blank_str + "\t" // squid result code
                            + duration + "\t"
                            + blank_str + "\t" // squid peer code
                            + message_no + "\t" // dg message no
                            + what + "\t"
                            + sweight + "\t"
                            + cat + "\t"
                            + groupname + "\t"
                            + stringgroup;
        }
        if (o.log_file_format > 6) {
            builtline += "\t";
            builtline += searchterms;
            builtline += "\t";
            builtline += flags;
        }

        if (!logsyslog)
            *logfile << builtline << std::endl; // append the line
        else
            syslog(LOG_INFO, "%s", builtline.c_str());
#ifdef E2DEBUG
        std::cerr << itemcount << " " << builtline << std::endl;
#endif
	if (o.e2_front_log)
		std::cout << builtline << std::endl;
        //    delete ipcpeersock; // close the connection

#ifdef ENABLE_EMAIL
        // do the notification work here, but fork for speed
        if (ldl->fg[filtergroup]->use_smtp == true) {

            // run through the gambit to find out of we're sending notification
            // because if we're not.. then fork()ing is a waste of time.

            // virus
            if ((wasscanned && wasinfected) && (ldl->fg[filtergroup]->notifyav)) {
                // Use a double fork to ensure child processes are reaped adequately.
                pid_t smtppid;
                if ((smtppid = fork()) != 0) {
                    // Parent immediately waits for first child
                    waitpid(smtppid, NULL, 0);
                } else {
                    // First child forks off the *real* process, but immediately exits itself
                    if (fork() == 0) {
                        // Second child - do stuff
                        setsid();
                        FILE *mail = popen(o.mailer.c_str(), "w");
                        if (mail == NULL) {
                            syslog(LOG_ERR, "Unable to contact defined mailer.");
                        } else {
                            fprintf(mail, "To: %s\n", ldl->fg[filtergroup]->avadmin.c_str());
                            fprintf(mail, "From: %s\n", ldl->fg[filtergroup]->mailfrom.c_str());
                            fprintf(mail, "Subject: %s\n", ldl->fg[filtergroup]->avsubject.c_str());
                            fprintf(mail, "A virus was detected by e2guardian.\n\n");
                            fprintf(mail, "%-10s%s\n", "Data/Time:", when.c_str());
                            if (who != blank_str)
                                fprintf(mail, "%-10s%s\n", "User:", who.c_str());
                            fprintf(mail, "%-10s%s (%s)\n", "From:", from.c_str(), ((clienthost.length() > 0) ? clienthost.c_str() : blank_str.c_str()));
                            fprintf(mail, "%-10s%s\n", "Where:", where.c_str());
                            // specifically, the virus name comes after message 1100 ("Virus or bad content detected.")
                            String swhat(what);
                            fprintf(mail, "%-10s%s\n", "Why:", swhat.after(o.language_list.getTranslation(1100).c_str()).toCharArray());
                            fprintf(mail, "%-10s%s\n", "Method:", how.c_str());
                            fprintf(mail, "%-10s%s\n", "Size:", ssize.c_str());
                            fprintf(mail, "%-10s%s\n", "Weight:", sweight.c_str());
                            if (cat.c_str() != NULL)
                                fprintf(mail, "%-10s%s\n", "Category:", cat.c_str());
                            fprintf(mail, "%-10s%s\n", "Mime type:", mimetype.c_str());
                            fprintf(mail, "%-10s%s\n", "Group:", ldl->fg[filtergroup]->name.c_str());
                            fprintf(mail, "%-10s%s\n", "HTTP resp:", stringcode.c_str());

                            pclose(mail);
                        }
                        // Second child exits
                        _exit(0);
                    }
                    // First child exits
                    _exit(0);
                }
            }

            // naughty OR virus
            else if ((isnaughty || (wasscanned && wasinfected)) && (ldl->fg[filtergroup]->notifycontent)) {
                byuser = ldl->fg[filtergroup]->byuser;

                // if no violations so far by this user/group,
                // reset threshold counters
                if (byuser) {
                    if (!violation_map[who]) {
                        // set the time of the first violation
                        timestamp_map[who] = time(0);
                        vbody_map[who] = "";
                    }
                } else if (!ldl->fg[filtergroup]->current_violations) {
                    // set the time of the first violation
                    ldl->fg[filtergroup]->threshold_stamp = time(0);
                    ldl->fg[filtergroup]->violationbody = "";
                }

                // increase per-user or per-group violation count
                if (byuser)
                    violation_map[who]++;
                else
                    ldl->fg[filtergroup]->current_violations++;

                // construct email report
                char *vbody_temp = new char[8192];
                sprintf(vbody_temp, "%-10s%s\n", "Data/Time:", when.c_str());
                vbody += vbody_temp;

                if ((!byuser) && (who != blank_str)) {
                    sprintf(vbody_temp, "%-10s%s\n", "User:", who.c_str());
                    vbody += vbody_temp;
                }
                sprintf(vbody_temp, "%-10s%s (%s)\n", "From:", from.c_str(), ((clienthost.length() > 0) ? clienthost.c_str() : blank_str.c_str()));
                vbody += vbody_temp;
                sprintf(vbody_temp, "%-10s%s\n", "Where:", where.c_str());
                vbody += vbody_temp;
                sprintf(vbody_temp, "%-10s%s\n", "Why:", what.c_str());
                vbody += vbody_temp;
                sprintf(vbody_temp, "%-10s%s\n", "Method:", how.c_str());
                vbody += vbody_temp;
                sprintf(vbody_temp, "%-10s%s\n", "Size:", ssize.c_str());
                vbody += vbody_temp;
                sprintf(vbody_temp, "%-10s%s\n", "Weight:", sweight.c_str());
                vbody += vbody_temp;
                if (cat.c_str() != NULL) {
                    sprintf(vbody_temp, "%-10s%s\n", "Category:", cat.c_str());
                    vbody += vbody_temp;
                }
                sprintf(vbody_temp, "%-10s%s\n", "Mime type:", mimetype.c_str());
                vbody += vbody_temp;
                sprintf(vbody_temp, "%-10s%s\n", "Group:", ldl->fg[filtergroup]->name.c_str());
                vbody += vbody_temp;
                sprintf(vbody_temp, "%-10s%s\n\n", "HTTP resp:", stringcode.c_str());
                vbody += vbody_temp;
                delete[] vbody_temp;

                // store the report with the group/user
                if (byuser) {
                    vbody_map[who] += vbody;
                    curv_tmp = violation_map[who];
                    stamp_tmp = timestamp_map[who];
                } else {
                    ldl->fg[filtergroup]->violationbody += vbody;
                    curv_tmp = ldl->fg[filtergroup]->current_violations;
                    stamp_tmp = ldl->fg[filtergroup]->threshold_stamp;
                }

                // if threshold exceeded, send mail
                if (curv_tmp >= ldl->fg[filtergroup]->violations) {
                    if ((ldl->fg[filtergroup]->threshold == 0) || ((time(0) - stamp_tmp) <= ldl->fg[filtergroup]->threshold)) {
                        // Use a double fork to ensure child processes are reaped adequately.
                        pid_t smtppid;
                        if ((smtppid = fork()) != 0) {
                            // Parent immediately waits for first child
                            waitpid(smtppid, NULL, 0);
                        } else {
                            // First child forks off the *real* process, but immediately exits itself
                            if (fork() == 0) {
                                // Second child - do stuff
                                setsid();
                                FILE *mail = popen(o.mailer.c_str(), "w");
                                if (mail == NULL) {
                                    syslog(LOG_ERR, "Unable to contact defined mailer.");
                                } else {
                                    fprintf(mail, "To: %s\n", ldl->fg[filtergroup]->contentadmin.c_str());
                                    fprintf(mail, "From: %s\n", ldl->fg[filtergroup]->mailfrom.c_str());

                                    if (byuser)
                                        fprintf(mail, "Subject: %s (%s)\n", ldl->fg[filtergroup]->contentsubject.c_str(), who.c_str());
                                    else
                                        fprintf(mail, "Subject: %s\n", ldl->fg[filtergroup]->contentsubject.c_str());

                                    fprintf(mail, "%i violation%s ha%s occurred within %i seconds.\n",
                                        curv_tmp,
                                        (curv_tmp == 1) ? "" : "s",
                                        (curv_tmp == 1) ? "s" : "ve",
                                        ldl->fg[filtergroup]->threshold);

                                    fprintf(mail, "%s\n\n", "This exceeds the notification threshold.");
                                    if (byuser)
                                        fprintf(mail, "%s", vbody_map[who].c_str());
                                    else
                                        fprintf(mail, "%s", ldl->fg[filtergroup]->violationbody.c_str());
                                    pclose(mail);
                                }
                                // Second child exits
                                _exit(0);
                            }
                            // First child exits
                            _exit(0);
                        }
                    }
                    if (byuser)
                        violation_map[who] = 0;
                    else
                        ldl->fg[filtergroup]->current_violations = 0;
                }
            } // end naughty OR virus
        } // end usesmtp
#endif

        continue; // go back to listening
    }
#ifdef E2DEBUG
    if( !logger_ttg)
        std::cerr << thread_id << "log_listener exiting with error" << std::endl;
#endif
    if (logfile) {
        logfile->close(); // close the file
        delete logfile;
    }
    } catch (...) {
        syslog(LOG_ERR,"%slog_listener caught unexpected exception - exiting", thread_id.c_str());
    }
    if (!logger_ttg)
        syslog(LOG_ERR, "%slog_listener exiting with error", thread_id.c_str());
    else if (o.logconerror)
        syslog(LOG_INFO,"%slog_listener exiting", thread_id.c_str());

    return; // It is only possible to reach here with an error
}

void accept_connections(int index) // thread to listen on a single listening socket
{
    try {
        unsigned int ct_type = serversockets.getType(index);
        int errorcount = 0;
        thread_id = "listen";
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
#ifdef E2DEBUG
                std::cerr << thread_id << "got connection from accept" << std::endl;
#endif
                if (peersock->getFD() > dstat.maxusedfd) dstat.maxusedfd = peersock->getFD();
                errorcount = 0;
                LQ_rec rec;
                rec.sock = peersock;
                rec.ct_type = ct_type;
                o.http_worker_Q.push(rec);
#ifdef E2DEBUG
                std::cerr << thread_id << "pushed connection to http_worker_Q" << std::endl;
#endif
            } else {
            	if (ttg) {
			if (peersock != nullptr) delete peersock;
			break;
		}
#ifdef E2DEBUG
                std::cerr << thread_id << "Error on accept: errorcount " << errorcount << " errno: " << err << std::endl;
#endif
                syslog(LOG_ERR, "%sError %d on accept: errorcount %d", thread_id.c_str(), err, errorcount);
                ++errorcount;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        };
        if (!ttg) syslog(LOG_ERR, "%sError count on accept exceeds 30", thread_id.c_str());
        serversockets[index]->close();
    } catch (...) {
       syslog(LOG_ERR,"%slistener thread caught unexpected exception exiting", thread_id.c_str());
    }
    if (o.logconerror) {
        syslog(LOG_INFO, "%slistener thread exiting", thread_id.c_str());
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
    logger_ttg = false;
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
            if (!is_daemonised) {
                std::cerr << thread_id << "Error creating server socket " << i << std::endl;
            }
            syslog(LOG_ERR, "%sError creating server socket %d", thread_id.c_str(), i);
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
    rc = setreuid((uid_t)-1, o.root_user);
#else
    rc = seteuid(o.root_user);
#endif
    if (rc == -1) {
        syslog(LOG_ERR, "%s%s", thread_id.c_str(), "Unable to seteuid() to bind filter port.");
#ifdef E2DEBUG
        std::cerr << thread_id << "Unable to seteuid() to bind filter port." << std::endl;
#endif
        delete[] serversockfds;
        return 1;
    }

    // we have to open/create as root before drop privs
    int pidfilefd = sysv_openpidfile(o.pid_filename);
    if (pidfilefd < 0) {
        syslog(LOG_ERR, "%s%s", thread_id.c_str(), "Error creating/opening pid file.");
        std::cerr << thread_id << "Error creating/opening pid file:" << o.pid_filename << std::endl;
        delete[] serversockfds;
        return 1;
    }

    // we expect to find a valid filter ip 0 specified in conf if multiple IPs are in use.
    // if we don't find one, bind to any, as per old behaviour.
    // XXX AAAARGH!
    if (o.filter_ip[0].length() > 6) {
        if (serversockets.bindAll(o.filter_ip, o.filter_ports)) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error binding server socket (is something else running on the filter port and ip?"
                          << std::endl;
            }
            syslog(LOG_ERR, "%sError binding server socket (is something else running on the filter port and ip?", thread_id.c_str());
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    } else {
        // listen/bind to a port (or ports) on any interface
        if (o.map_ports_to_ips) {
            if (serversockets.bindSingle(o.filter_port)) {
                if (!is_daemonised) {
                    std::cerr << thread_id << "Error binding server socket: [" << o.filter_port << "] (" << strerror(errno) << ")"
                              << std::endl;
                }
                syslog(LOG_ERR, "%sError binding server socket: [%d] (%s)", thread_id.c_str(), o.filter_port, strerror(errno));
                close(pidfilefd);
                delete[] serversockfds;
                return 1;
            }
        } else {
            if (serversockets.bindSingleM(o.filter_ports)) {
                if (!is_daemonised) {
                    std::cerr << thread_id << "Error binding server sockets: (" << strerror(errno) << ")" << std::endl;
                }
                syslog(LOG_ERR, "%sError binding server sockets  (%s)", thread_id.c_str(), strerror(errno));
                close(pidfilefd);
                delete[] serversockfds;
                return 1;
            }
        }
    }

    if (o.transparenthttps_port > 0) {
        if (serversockets.bindSingle(serversocktopproxy++,o.transparenthttps_port, CT_THTTPS)) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error binding server thttps socket: (" << strerror(errno) << ")" << std::endl;
            }
            syslog(LOG_ERR, "%sError binding server thttps socket  (%s)", thread_id.c_str(), strerror(errno));
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    };

    if (o.icap_port > 0) {
        if (serversockets.bindSingle(serversocktopproxy,o.icap_port, CT_ICAP)) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error binding server icap socket: (" << strerror(errno) << ")" << std::endl;
            }
            syslog(LOG_ERR, "%sError binding server icap socket  (%s)", thread_id.c_str(), strerror(errno));
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    };

// Made unconditional for same reasons as above
//if (needdrop)
#ifdef HAVE_SETREUID
    rc = setreuid((uid_t)-1, o.proxy_user);
#else
    rc = seteuid(o.proxy_user); // become low priv again
#endif
    if (rc == -1) {
        syslog(LOG_ERR, "%sUnable to re-seteuid()", thread_id.c_str());
#ifdef E2DEBUG
        std::cerr << thread_id << "Unable to re-seteuid()" << std::endl;
#endif
        close(pidfilefd);
        delete[] serversockfds;
        return 1; // seteuid failed for some reason so exit with error
    }

    if (serversockets.listenAll(256)) { // set it to listen mode with a kernel
        // queue of 256 backlog connections
        if (!is_daemonised) {
            std::cerr << thread_id << "Error listening to server socket" << std::endl;
        }
        syslog(LOG_ERR, "%sError listening to server socket", thread_id.c_str());
        close(pidfilefd);
        delete[] serversockfds;
        return 1;
    }

    if (!daemonise()) {
        // detached daemon
        if (!is_daemonised) {
            std::cerr << thread_id << "Error daemonising" << std::endl;
        }
        syslog(LOG_ERR, "%sError daemonising", thread_id.c_str());
        close(pidfilefd);
        delete[] serversockfds;
        return 1;
    }

#ifdef __SSLMITM
    //init open ssl
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    if (o.use_openssl_conf) {
    	if(o.have_openssl_conf) {
		if (CONF_modules_load_file(o.openssl_conf_path.c_str(), nullptr,0) != 1) {
		syslog(LOG_ERR, "Error reading openssl config file %s", o.openssl_conf_path.c_str());
		return false;
		}
	} else {
		if (CONF_modules_load_file(nullptr, nullptr,0) != 1) {
		syslog(LOG_ERR, "Error reading default openssl config files");
		return false;
		}
	}
    }
    SSL_library_init();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    init_ssl_locks();
#endif
#endif  // end __SSLMITM

    // this has to be done after daemonise to ensure we get the correct PID.
    rc = sysv_writepidfile(pidfilefd); // also closes the fd
    if (rc != 0) {
        syslog(LOG_ERR, "%sError writing to the e2guardian.pid file: %s", thread_id.c_str(), strerror(errno));
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
    if (!o.no_logger) {
        std::thread log_thread(log_listener, o.log_location, false, o.log_syslog,o.log_Q);
        log_thread.detach();
#ifdef E2DEBUG
    std::cerr << thread_id << "log_listener thread created" << std::endl;
#endif
    }

    if(o.log_requests) {
        std::thread RQlog_thread(log_listener, o.RQlog_location, true, false,o.RQlog_Q);
        RQlog_thread.detach();
#ifdef E2DEBUG
        std::cerr << thread_id << "RQlog_listener thread created" << std::endl;
#endif

    }

// I am the main thread here onwards.

#ifdef E2DEBUG
    std::cerr << thread_id << "Master thread created threads" << std::endl;
#endif


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
        syslog(LOG_ERR, "%sError setting sigmask", thread_id.c_str());
        return 1;
    }

#ifdef E2DEBUG
    std::cerr << thread_id << "sig handlers done" << std::endl;
#endif

    dystat->busychildren = 0; // to keep count of our children
    //

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
#ifdef E2DEBUG
    std::cerr << thread_id << "http_worker threads created" << std::endl;
#endif

    //   set listener threads going

    std::vector <std::thread> listen_threads;
    listen_threads.reserve(serversocketcount);
    for (int i = 0; i < serversocketcount; i++) {
        listen_threads.push_back(std::thread(accept_connections, i));
    }
    for (auto &i : listen_threads) {
        i.detach();
    }
#ifdef E2DEBUG
    std::cerr << "listen  threads created" << std::endl;
#endif

    time_t tmaxspare;

    time(&tmaxspare);

    failurecount = 0; // as we don't exit on an error with select()
    // due to the fact that these errors do happen
    // every so often on a fully working, but busy
    // system, we just watch for too many errors
    // consecutivly.

    is_starting = true;

    if (reloadconfig) {
        syslog(LOG_INFO, "Reconfiguring E2guardian: done");
    } else {
        syslog(LOG_INFO, "Started successfully.");
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
#ifdef E2DEBUG
            std::cerr << thread_id << "gentle reload activated" << std::endl;
#endif
            syslog(LOG_INFO, "%sReconfiguring E2guardian: gentle reload starting", thread_id.c_str());
            if (o.createLists(++reload_cnt))
                syslog(LOG_INFO, "%sReconfiguring E2guardian: gentle reload completed", thread_id.c_str());
            else
                syslog(LOG_INFO, "%sReconfiguring E2guardian: gentle reload failed", thread_id.c_str());

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
                syslog(LOG_INFO, "%sUnexpected error from sigtimedwait() %d %s", thread_id.c_str(), errno, strerror(errno));
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

#ifdef E2DEBUG
                std::cerr << "signal:" << rc << std::endl;
#endif
                if (o.logconerror) {
                    syslog(LOG_INFO, "%ssigtimedwait() signal %d recd:", thread_id.c_str(), rsig);
                }
            }
        }
#else
	// other posix compliant platforms
        timeout.tv_sec = 5;
        rc = sigtimedwait(&signal_set, NULL, &timeout);
        if (rc < 0) {
            if (errno != EAGAIN) {
                syslog(LOG_INFO, "%sUnexpected error from sigtimedwait() %d %s", thread_id.c_str(), errno, strerror(errno));
            }
        } else {
            if (rc == SIGUSR1)
                gentlereload = true;
            if (rc == SIGTERM)
                ttg = true;
            if (rc == SIGHUP)
                gentlereload = true;
#ifdef E2DEBUG
            std::cerr << "signal:" << rc << std::endl;
#endif
            if (o.logconerror) {
                syslog(LOG_INFO, "%ssigtimedwait() signal %d recd:", thread_id.c_str(), rc);
            }
        }
#endif   // end __OpenBSD__ else

        int q_size = o.http_worker_Q.size();
#ifdef E2DEBUG
        std::cerr << thread_id << "busychildren:" << dystat->busychildren << " worker Q size:" << q_size << std::endl;
#endif
        if( o.dstat_log_flag) {
            if (q_size > 10) {
                syslog(LOG_INFO,
                       "%sWarning: all %d http_worker threads are busy and %d connections are waiting in the queue.",
                       thread_id.c_str(), o.http_workers, q_size);
            }
        } else {
            int busy_child = dystat->busychildren;
            if (busy_child > (o.http_workers - 10))
                syslog(LOG_INFO, "%sWarning system is full : max httpworkers: %d Used: %d", thread_id.c_str(),
                       o.http_workers, busy_child);
        }

        //      if (is_starting)

        time_t now = time(NULL);


        if (o.dstat_log_flag && (now >= dystat->end_int))
            dystat->reset();
    }


    //  tidy-up

    sigfillset(&signal_set);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

    syslog(LOG_INFO,"%sStopping", thread_id.c_str());

    if (o.monitor_flag_flag)
       monitor_flag_set(false);
    if (o.monitor_helper_flag)
        tell_monitor(false); // tell monitor that we are not accepting any more connections

    if (o.logconerror) {
        syslog(LOG_INFO,"%ssending null socket to http_workers to stop them", thread_id.c_str());
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
    //syslog(LOG_INFO,"2nd wait complete");
    logger_ttg = true;
    std::string nullstr("");
    o.log_Q->push(nullstr);
    if (o.log_requests) {
        o.RQlog_Q->push(nullstr);
    }

    if (o.logconerror) {
        syslog(LOG_INFO,"%sstopping any remaining connections", thread_id.c_str());
    }
    serversockets.self_connect();   // stop accepting connections
    if (o.logconerror) {
        syslog(LOG_INFO,"%sconnections stopped", thread_id.c_str());
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    if (o.dstat_log_flag) dystat->close();

#ifdef __SSLMITM
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    kill_ssl_locks();
#endif
#endif

    delete[] serversockfds;

    if (o.logconerror) {
        syslog(LOG_INFO, "%s%s",  thread_id.c_str(), "Main thread exiting.");
    }
    return 0;
}
