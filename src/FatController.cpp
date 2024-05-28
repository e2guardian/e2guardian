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

std::atomic<bool> ttg;
std::atomic<bool> e2logger_ttg;
std::atomic<bool> gentlereload;
std::atomic<bool> reloadconfig;
std::atomic<int> reload_cnt;
std::atomic<bool> rotate_access;
std::atomic<bool> rotate_request;
std::atomic<bool> rotate_dstat;

extern std::atomic<bool> g_is_starting;

extern OptionContainer o;
extern bool is_daemonised;

pid_t master_pid = 0;

void stat_rec::clear() {
    conx = 0;
    reqs = 0;
};

void stat_rec::start(bool firsttime = true) {

    if (firsttime) {
        clear();
        start_int = time(NULL);
        end_int = start_int + o.dstat.dstat_interval;
        maxusedfd = 0;
    }

    if (o.dstat.dstat_log_flag) {
        // now opened by Logger
        //mode_t old_umask;
        //old_umask = umask(S_IWGRP | S_IWOTH);
        //fs = fopen(o.dstat_location.c_str(), "a");
        std::string outmess;
        if (o.dstat.stats_human_readable) {
            outmess = "time		        httpw	busy	httpwQ	logQ	conx	conx/s	 reqs	reqs/s	maxfd	LCcnt";
        } else {
            outmess = "time		httpw	busy	httpwQ	logQ	conx	conx/s	reqs	reqs/s	maxfd	LCcnt";
        }
        E2LOGGER_dstatslog(outmess);
        e2logger.flush(LoggerSource::dstatslog);
    };
};

void stat_rec::reset() {
    time_t now = time(NULL);
    int bc = busychildren;
    long period = now - start_int;
    long cnx = (long) conx;
    long rqx = (long) reqs;
    int mfd = maxusedfd;
    int LC = o.LC_cnt;
    // clear and reset stats now so that stats are less likely to be missed
    clear();
    if ((end_int + o.dstat.dstat_interval) > now)
        start_int = end_int;
    else
        start_int = now;

    end_int = start_int + o.dstat.dstat_interval;

    if (rotate_dstat) {
        e2logger.rotate(LoggerSource::dstatslog);
        start(false);  // output header
        rotate_dstat = false;
    }

    char outbuff[201];

    long cps = cnx / period;
    long rqs = rqx / period;
    if (o.dstat.stats_human_readable) {
        struct tm *timeinfo;
        time(&now);
        timeinfo = localtime(&now);
        char buffer[50];
        strftime(buffer, 50, "%Y-%m-%d %H:%M", timeinfo);
        snprintf(outbuff, 200, "%s	%d	%d	%d	%d	%ld	%ld	%ld	 %ld	%d	 %d", buffer,
                 o.proc.http_workers,
                 bc, o.http_worker_Q.size(), o.log.log_Q->size(), cnx, cps, rqx, rqs, mfd, LC);
    } else {
        snprintf(outbuff, 200, "%ld	%d	%d	%d	%d	%ld	%ld	%ld	%ld	%d	%d", now,
                 o.proc.http_workers,
                 bc, o.http_worker_Q.size(), o.log.log_Q->size(), cnx, cps, rqx, rqs, mfd, LC);
    }
    std::string outs(outbuff);
    E2LOGGER_dstatslog(outs);
    e2logger.flush(LoggerSource::dstatslog);

    //fflush(fs);
};

void stat_rec::close() {
    if (fs != NULL) fclose(fs);
};


//int cache_erroring; // num cache errors reported by children
//int restart_cnt = 0;
//int restart_numchildren; // numchildren at time of gentle restart
//int hup_index;
//int gentle_to_hup = 0;

//bool gentle_in_progress = false;
int top_child_fds; // cross platform maxchildren position in children array
int failurecount;
int serversocketcount;
SocketArray serversockets; // the sockets we will listen on for connections
Socket *peersock(NULL); // the socket which will contain the connection

//String peersockip; // which will contain the connection ip


void monitor_flag_set(bool action) {

    String fulink = o.monitor.monitor_flag_prefix;
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
        E2LOGGER_error("Unable to open monitor_flag ", ftouch, " for writing");
        o.monitor.monitor_flag_flag = false;
    }
    fclose(fs);
    if (unlink(fulink.c_str()) == -1) {
        E2LOGGER_error("Unable to unlink monitor_flag ", fulink, " error: ", strerror(errno));
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
void log_listener(Queue<std::string> *log_Q, bool is_RQlog);

// fork off into background
bool daemonise(int pidfilefd);
// create specified amount of child threads

//void handle_connections(int tindex);  // needs changing to be threadish

// setuid() to proxy user (not just seteuid()) - used by child processes & logger/URL cache for security & resource usage reasons
bool drop_priv_completely();

// IMPLEMENTATION

// completely drop our privs - i.e. setuid, not just seteuid
bool drop_priv_completely() {
    // This is done to solve the problem where the total processes for the
    // uid rather than euid is taken for RLIMIT_NPROC and so can't fork()
    // as many as expected.
    // It is also more secure.
    //
    // Suggested fix by Lawrence Manning Tue 25th February 2003
    //

    int rc = seteuid(o.proc.root_user); // need to be root again to drop properly
    if (rc == -1) {
        E2LOGGER_error("Unable to seteuid(suid)");
        return false; // setuid failed for some reason so exit with error
    }
    rc = setuid(o.proc.proxy_user);
    if (rc == -1) {
        E2LOGGER_error("Unable to setuid()");
        return false; // setuid failed for some reason so exit with error
    }
    return true;
}

// Fork ourselves off into the background
bool daemonise(int pidfileid) {

    int nullfd = -1;
    if ((nullfd = open("/dev/null", O_WRONLY, 0)) == -1) {
        E2LOGGER_error("Couldn't open /dev/null");
        return false;
    }

    pid_t pid;
    if ((pid = fork()) < 0) {
        // Error!!
        close(nullfd);
        return false;
    } else if (pid != 0) {// parent goes...A
        master_pid = pid;
        if (nullfd != -1) {
            close(nullfd);
        }
        int rc = sysv_writepidfile(pidfileid, master_pid);
        if (rc != 0) {
            E2LOGGER_error("Error writing to the e2guardian.pid file: ", strerror(errno));
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
        E2LOGGER_error(" Can't change / directory !");
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
void handle_connections(int tindex) {
    (thread_id = "hw") += std::to_string(tindex) += ": ";

    try {
        while (!ttg) {  // extra loop in order to delete and create ConnentionHandler on new lists or error
            ConnectionHandler h;    // the class that handles the connections
            String ip;

            while (!ttg) {
                DEBUG_debug(" waiting connection on http_worker_Q ");
                LQ_rec rec = o.http_worker_Q.pop();
                Socket *peersock = rec.sock;
                DEBUG_debug(" popped connection from http_worker_Q");
                if (ttg) break;

                String peersockip = peersock->getPeerIP();
                if (peersock->getFD() < 0 || peersockip.length() < 7) {
//            if (o.conn.logconerror)
                    E2LOGGER_info("Error accepting. (Ignorable)");
                    continue;
                }
                ++dystat->busychildren;
                ++dystat->conx;
#ifdef DEBUG_LOW
                int rc = h.handlePeer(*peersock, peersockip, dystat, rec.ct_type); // deal with the connection
                DEBUG_debug("handle_peer returned: ", rc);
#else
                h.handlePeer(*peersock, peersockip, dystat, rec.ct_type); // deal with the connection
#endif

                --dystat->busychildren;
                if(peersock != nullptr) delete peersock;
                break;
            };
        };
    } catch (...) {
        E2LOGGER_error("worker thread caught unexpected exception - exiting");
    }
}


// *
// *
// * end of worker thread code
// *
// *


#ifdef REMOVE_IN_55
void tell_monitor(bool active) //may not be needed
{

    String buff(o.monitor_helper);
    String buff1;

    if (active)
        buff1 = " start";
    else
        buff1 = " stop";

    E2LOGGER_error("Monitorhelper called: ", buff, buff1);
    pid_t childid;
    childid = fork();

    if (childid == -1) {
        E2LOGGER_error("Unable to fork to tell monitorhelper error: ", strerror(errno));
        return;
    };

    if (childid == 0) { // Am the child
        int rc = seteuid(o.proc.root_user);
        if (rc != -1) {
            int systemreturn = execl(buff.c_str(), buff.c_str(), buff1.c_str(),
                                     (char *) NULL); // should not return from call
            if (systemreturn == -1) {
                E2LOGGER_error("Unable to exec: ", buff, buff1, " : errno ", errno, " ", strerror(errno));
                exit(0);
            }
        } else {
            E2LOGGER_error("Unable to set uid root");
            exit(0);
        }
    };

    if (childid > 0) { // Am the parent
        int rc;
        int status;
        rc = waitpid(childid, &status, 0);
        if (rc == -1) {
            E2LOGGER_error("Wait for monitorhelper returned : errno ", strerror(errno));
            return;
        };
        if (WIFEXITED(status)) {
            return;
        } else {
            E2LOGGER_error("Monitorhelper exited abnormally");
            return;
        };
    };
};
#endif

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
        DEBUG_debug(" -exception while creating proxysock: ", e.what());
    }
    E2LOGGER_error("Proxy is not responding - Waiting for proxy to respond");
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
            E2LOGGER_error("Proxy now responding - resuming after %d seconds", wait_time);
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
                E2LOGGER_error("Proxy not responding - still waiting after %d seconds", wait_time);
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

void log_listener(Queue<std::string> *log_Q, bool is_RQlog) {
    if (is_RQlog)
        thread_id = "RQlog: ";
    else
        thread_id = "log: ";

    try {
        DEBUG_trace("log listener started");

#ifdef ENABLE_EMAIL  // no longer needed - replace with some sort of external script reading alert log??
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
        int port = 80, isnaughty = 0, isexception = 0, issemiexception = 0, code = 200, naughtytype = 0;
        int do_access_log = 0, do_alert_log =0;
        int cachehit = 0, wasinfected = 0, wasscanned = 0, filtergroup = 0;
        long tv_sec = 0, tv_usec = 0, endtv_sec = 0, endtv_usec = 0;
        int contentmodified = 0, urlmodified = 0, headermodified = 0;
        int headeradded = 0;

        String server("");
        // Get server name - only needed for formats 5 & 7
        if ((o.log.log_file_format == 5) || (o.log.log_file_format == 7)) {
            server = o.net.server_name;
        }

        std::string semiexception_word = o.language_list.getTranslation(51);
        semiexception_word = "*" + semiexception_word + "* ";
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

        if (o.log.use_dash_for_blanks)
            blank_str = "-";
        else
            blank_str = "";


        while (!e2logger_ttg) { // loop, essentially, for ever
            std::string loglines;
            loglines.append(log_Q->pop());  // get logdata from queue
            if (e2logger_ttg) break;
            if (is_RQlog && rotate_request) {
                e2logger.rotate(LoggerSource::requestlog);
                rotate_request = false;
            } else if (!is_RQlog && rotate_access) {
                e2logger.rotate(LoggerSource::accesslog);
                rotate_access = false;
            }
            DEBUG_debug("received a log request");

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
            std::shared_ptr <LOptionContainer> ldl;
            ldl = o.currentLists();

            while (std::getline(iss, logline)) {
                // Loop around reading in data, because we might have huge URLs
                std::string s;

                if (o.log.use_dash_for_blanks && logline == "") {
                    s = "-";
                } else if (!o.log.use_dash_for_blanks && logline == "-") {
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
                        if (filtergroup < 0 || filtergroup > o.filter.numfg) filtergroup = 0;
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
                        break;
                    case 33:
                        do_access_log = atoi(logline.c_str());
                        break;
                    case 34:
                        do_alert_log = atoi(logline.c_str());
                        break;
                    case 35:
                        issemiexception = atoi(logline.c_str());
                        error = false;
                        break;
                }
                itemcount++;
            }


            // don't build the log line if we couldn't read all the component parts
            if (error) {
                E2LOGGER_error("Error in logline ", itemcount, " ", loglines);
                continue;
            }

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
            } else if (isexception && (o.log.log_exception_hits == 2)) {
                if (issemiexception) {
                    what = semiexception_word + what;
                } else {
                    what = exception_word + what;
                }
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
            if (o.log.log_timestamp || (o.log.log_file_format == 3)
                || (o.log.log_file_format > 4)) {
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


            if ((o.log.log_file_format <= 2) || (o.log.log_file_format == 4)) {
                // "when" not used in format 3, and not if logging timestamps instead in formats 5-8
                //time_t now = time(NULL);
                time_t now = endtv_sec;
                char date[32];
                struct tm *tm = localtime(&now);
                strftime(date, sizeof date, "%Y.%m.%d %H:%M:%S", tm);
                when = date;
                // append timestamp if desired
                if (o.log.log_timestamp)
                    when += " " + utime;
            }

            // blank out IP, hostname and username if desired
            if (o.log.anonymise_logs) {
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

            switch (o.log.log_file_format) {
                case 4:
                    builtline = when + "\t" + who + "\t" + from + "\t" + where + "\t" + what + "\t" + how
                                + "\t" + ssize + "\t" + sweight + "\t" + cat + "\t" + stringgroup + "\t"
                                + stringcode + "\t" + mimetype + "\t" + clienthost + "\t" + groupname
                                #ifdef SG_LOGFORMAT
                                + "\t" + useragent + "\t\t" + o.log.logid_1 + "\t" + o.log.prod_id + "\t"
                    + params + "\t" + o.log.logid_2 + "\t" + postdata;
                                #else
                                + "\t" + useragent + "\t" + params + "\t" + o.log.logid_1 + "\t" + o.log.logid_2 + "\t" +
                                postdata;
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
                    hier += o.net.proxy_ip;
                    builtline =
                            utime + " " + duration + " " + ((clienthost.length() > 0) ? clienthost : from) + " " +
                            hitmiss +
                            " " + ssize + " "
                            + how + " " + where + " " + who + " " + hier + " " + mimetype;
                    break;
                }
                case 2:
                    builtline =
                            "\"" + when + "\",\"" + who + "\",\"" + from + "\",\"" + where + "\",\"" + what + "\",\""
                            + how + "\",\"" + ssize + "\",\"" + sweight + "\",\"" + cat + "\",\"" + stringgroup +
                            "\",\""
                            + stringcode + "\",\"" + mimetype + "\",\"" + clienthost + "\",\"" +
                            groupname + "\",\""
                            + useragent + "\",\"" + params + "\",\"" + o.log.logid_1 + "\",\"" + o.log.logid_2 + "\",\"" +
                            postdata + "\"";
                    break;
                case 1:
                    builtline = when + " " + who + " " + from + " " + where + " " + what + " "
                                + how + " " + ssize + " " + sweight + " " + cat + " " + stringgroup + " "
                                + stringcode + " " + mimetype + " " + clienthost + " " + groupname + " "
                                + useragent + " " + params + " " + o.log.logid_1 + " " + o.log.logid_2 + " " + postdata;
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
                    if (o.log.log_client_host_and_ip) {
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
                                 + (o.log.log_user_agent ? useragent : blank_str) + "\t"
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
            if (o.log.log_file_format > 6) {
                builtline += "\t";
                builtline += searchterms;
                builtline += "\t";
                builtline += flags;
            }

            // Send to Log
            DEBUG_trace("Now sending to Log");
            if (is_RQlog) {
                E2LOGGER_requestlog(builtline);
            } else {
                if(do_access_log) {
                    E2LOGGER_accesslog(builtline);
                }
                if(do_alert_log) {
                    E2LOGGER_alertlog(builtline);
                }
                E2LOGGER_responselog(builtline);  // Will only work if responselog is enabled.
            }


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
                                E2LOGGER_error("Unable to contact defined mailer.");
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
                                        E2LOGGER_error("Unable to contact defined mailer.");
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
        if (!e2logger_ttg)
                DEBUG_debug("log_listener exiting with error");

    } catch (...) {
        E2LOGGER_error("log_listener caught unexpected exception - exiting");
    }
    if (!e2logger_ttg) {
        E2LOGGER_error("log_listener exiting with error");
    } else if (o.conn.logconerror) {
        E2LOGGER_error("log_listener exiting");
    }

    return; // It is only possible to reach here with an error
}

void accept_connections(int index) // thread to listen on a single listening socket
{
    try {
        unsigned int ct_type = serversockets.getType(index);
        int errorcount = 0;
        thread_id = "listen_";
        thread_id += std::to_string(index);
        thread_id += "_";
        switch (ct_type) {
            case CT_PROXY:
                thread_id += "proxy: ";
                break;
            case CT_PROXY_TLS:
                thread_id += "tls_proxy: ";
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
                DEBUG_debug("got connection from accept");

                if (peersock->getFD() > dstat.maxusedfd) dstat.maxusedfd = peersock->getFD();
                errorcount = 0;
                LQ_rec rec;
                rec.sock = peersock;
                rec.ct_type = ct_type;
                o.http_worker_Q.push(rec);

                DEBUG_debug("pushed connection to http_worker_Q");
            } else {
                if (ttg) {
                    if (peersock != nullptr) delete peersock;
                    break;
                }
                E2LOGGER_error("Error on accept: errorcount ", String(errorcount), " errno: ", String(err));

                ++errorcount;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        };
        if (!ttg)
            E2LOGGER_error("Error count on accept exceeds 30");
        serversockets[index]->close();
    } catch (...) {
        E2LOGGER_error("listener thread caught unexpected exception exiting");
    }
    if (o.conn.logconerror) {
        E2LOGGER_info("listener thread exiting");
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
    e2logger_ttg = false;
    reloadconfig = false;
    gentlereload = false;
    reload_cnt = 0;
    rotate_request = false;
    rotate_access = false;
    rotate_dstat = false;

    o.lm.garbageCollect();
    thread_id = "master: ";

    // allocate & create our server sockets
        if (o.net.filter_ip.size() > 0) {
            serversocketcount = o.net.filter_ip.size() * o.net.filter_ports.size();
            if (!o.net.TLS_filter_ports.empty()) {
                serversocketcount += (o.net.filter_ip.size() * o.net.TLS_filter_ports.size());
            }
        } else {
            serversocketcount = o.net.filter_ports.size() + o.net.TLS_filter_ports.size();
        }

    int serversocktopproxy = serversocketcount;

    if (o.net.transparenthttps_port > 0)
        ++serversocketcount;
    if (o.net.icap_port > 0)
        ++serversocketcount;

    serversockets.reset(serversocketcount);
    int *serversockfds = serversockets.getFDAll();
    //std::thread *listen_treads[serversocketcount];
    for (int i = 0; i < serversocketcount; i++) {
        // if the socket fd is not +ve then the socket creation failed
        if (serversockfds[i] < 0) {
            E2LOGGER_error("Error creating server socket ", String(i));
            delete[] serversockfds;
            return 1;
        }
    }

    DEBUG_trace("seteuiding for low port binding/pidfile creation");
     if (!o.proc.become_root_user()) {
        E2LOGGER_error("Unable to seteuid() to bind filter port.");
        delete[] serversockfds;
        return 1;
    }

    // we have to open/create as root before drop privs
    int pidfilefd = sysv_openpidfile(o.proc.pid_filename);
    if (pidfilefd < 0) {
        E2LOGGER_error("Error creating/opening pid file.");
        delete[] serversockfds;
        return 1;
    }

    int ss_index = 0;
    // we expect to find a valid filter ip 0 specified in conf if multiple IPs are in use.
    if (o.net.filter_ip[0].length() > 6) {
        if (serversockets.bindAll(o.net.filter_ip, o.net.filter_ports,ss_index,CT_PROXY)) {
            E2LOGGER_error("Error binding HTTP proxy server socket (is something else running on the filter port and ip?");
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
        if (!o.net.TLS_filter_ports.empty()) {
            if (serversockets.bindAll(o.net.filter_ip, o.net.TLS_filter_ports, ss_index, CT_PROXY_TLS)) {
                E2LOGGER_error(
                        "Error binding TLS proxy server socket (is something else running on the filter port and ip?)");
                close(pidfilefd);
                delete[] serversockfds;
                return 1;
            }
        }
    } else {
        // listen/bind to a port (or ports) on any interface
            if (serversockets.bindSingleM(o.net.filter_ports, ss_index, CT_PROXY)) {
                E2LOGGER_error("Error binding HTTP proxy server sockets: (", strerror(errno), ")");
                close(pidfilefd);
                delete[] serversockfds;
                return 1;
            }
        if (serversockets.bindSingleM(o.net.TLS_filter_ports, ss_index, CT_PROXY_TLS)) {
            E2LOGGER_error("Error binding TLS proxy server sockets: (", strerror(errno), ")");
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    }

    if (o.net.transparenthttps_port > 0) {
        if (serversockets.bindSingle(serversocktopproxy++, o.net.transparenthttps_port, CT_THTTPS)) {
            E2LOGGER_error("Error binding server thttps socket: (", strerror(errno), ")");
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    };

    if (o.net.icap_port > 0) {
        if (serversockets.bindSingle(serversocktopproxy, o.net.icap_port, CT_ICAP)) {
            E2LOGGER_error("Error binding server icap socket: (", strerror(errno), ")");
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
        E2LOGGER_error("%sUnable to re-seteuid()");
        close(pidfilefd);
        delete[] serversockfds;
        return 1; // seteuid failed for some reason so exit with error
    }

    if (serversockets.listenAll(256)) { // set it to listen mode with a kernel
        // queue of 256 backlog connections
        E2LOGGER_error("Error listening to server socket");
        close(pidfilefd);
        delete[] serversockfds;
        return 1;
    }

#ifndef DEBUG_LOW      // remain in foreground when in low debug mode
    if (!(is_daemonised||o.proc.no_daemon)) {
        if (!daemonise(pidfilefd)) {
            // detached daemon
            E2LOGGER_error("Error daemonising");
            close(pidfilefd);
            delete[] serversockfds;
            return 1;
        }
    }
#endif

    //init open ssl
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_digests();
    if (o.cert.use_openssl_conf) {
        if (o.cert.have_openssl_conf) {
            if (CONF_modules_load_file(o.cert.openssl_conf_path.c_str(), nullptr, 0) != 1) {
                E2LOGGER_error("Error reading openssl config file ", o.cert.openssl_conf_path.c_str());
                return false;
            }
        } else {
            if (CONF_modules_load_file(nullptr, nullptr, 0) != 1) {
                E2LOGGER_error("Error reading default openssl config files");
                return false;
            }
        }
    }
    SSL_library_init();

    // only done now if not daemonised as pidfile must be written from parent when forking - required so that systemd will pick up master pid from pidfile
    if (!is_daemonised) {
        rc = sysv_writepidfile(pidfilefd, 0); // also closes the fd
        if (rc != 0) {
            E2LOGGER_error("Error writing to the e2guardian.pid file: ", strerror(errno));
            delete[] serversockfds;
            return false;
        }
    }

    // We are now a daemon so all errors need to go in the syslog, rather
    // than being reported on screen as we've detached from the console and
    // trying to write to stdout will not be nice.

    g_is_starting = false;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

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
            E2LOGGER_error("Error setting sigmask");
            return 1;
        }

        DEBUG_trace("sig handlers done");


    // Now start creating threads so main thread can just handle signals, list reloads and stats
    // This removes need for select and/or epoll greatly simplifying the code
    // Threads are created for logger, a separate thread for each listening port
    // and an array of worker threads to deal with the work.
    //if (!o.no_logger) {
    if (e2logger.isEnabled(LoggerSource::accesslog)) {
        std::thread log_thread(log_listener, o.log.log_Q, false);
        log_thread.detach();
        DEBUG_trace("log_listener thread created");
    }

    //if(o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        std::thread RQlog_thread(log_listener, o.log.RQlog_Q, true);
        RQlog_thread.detach();
        DEBUG_trace("RQlog_listener thread created");
    }


    dystat->busychildren = 0; // to keep count of our children

    // worker thread generation
    std::vector <std::thread> http_wt;
    http_wt.reserve(o.proc.http_workers);

    int i;
    for (i = 0; i < o.proc.http_workers; i++) {
        http_wt.push_back(std::thread(handle_connections, i));
    }
    for (auto &i : http_wt) {
        i.detach();
    }

    DEBUG_trace("http_worker threads created");

    //   set listener threads going
    std::vector <std::thread> listen_threads;
    listen_threads.reserve(serversocketcount);
    for (int i = 0; i < serversocketcount; i++) {
        listen_threads.push_back(std::thread(accept_connections, i));
    }
    for (auto &i : listen_threads) {
        i.detach();
    }

    DEBUG_trace("listen  threads created");

    // I am the main thread here onwards.
    DEBUG_trace("Master thread created threads");

    time_t tmaxspare;

    time(&tmaxspare);

    failurecount = 0; // as we don't exit on an error with select()
    // due to the fact that these errors do happen
    // every so often on a fully working, but busy
    // system, we just watch for too many errors
    // consecutivly.

    is_starting = true;

    if (reloadconfig) {
        E2LOGGER_info("Reconfiguring E2guardian: done");
    } else {
        E2LOGGER_info("Started successfully.");
        dystat->start(true);
    }
    reloadconfig = false;

    if (is_starting) {
        if (o.monitor.monitor_flag_flag)
            monitor_flag_set(true);
        // if (o.monitor_helper_flag) {
        //     tell_monitor(true);
        // }
        is_starting = false;
    }

    while (failurecount < 30 && !ttg && !reloadconfig) {

        // loop, essentially, for ever until 30
        // consecutive errors in which case something
        // is badly wrong.
        // OR, its timetogo - got a sigterm
        // OR, we need to exit to reread config
        if (gentlereload) {
            DEBUG_trace("gentle reload activated");

            E2LOGGER_info("Reconfiguring E2guardian: gentle reload starting");
            if (o.createLists(++reload_cnt)) {
                E2LOGGER_info("Reconfiguring E2guardian: gentle reload completed");
            } else {
                reload_cnt--;
                E2LOGGER_info("%sReconfiguring E2guardian: gentle reload failed");
            }

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
                    E2LOGGER_info("Unexpected error from sigtimedwait(): ", String(errno), " ", strerror(errno));
                }
            } else {
                if (rsig == SIGUSR1) {
                    rotate_access = true;
                    rotate_request = true;
                    rotate_dstat = true;
                }
                if (rsig == SIGTERM)
                    ttg = true;
                if (rsig == SIGHUP)
                    gentlereload = true;
                if (rsig != SIGALRM) {
                    // unset alarm
                    timeout.it_value.tv_sec = 0;
                    //timer_settime(timerid,0,&timeout, NULL);
                    setitimer(ITIMER_REAL, &timeout, NULL);

                    DEBUG_debug("signal:", String(rc));
                    if (o.conn.logconerror) {
                        E2LOGGER_info("sigtimedwait() signal recd:", String(rsig) );
                    }
                }
            }
#else
        // other posix compliant platforms
        timeout.tv_sec = 5;
        rc = sigtimedwait(&signal_set, NULL, &timeout);
        if (rc < 0) {
            if (errno != EAGAIN) {
                E2LOGGER_info("Unexpected error from sigtimedwait():", String(errno), " ", strerror(errno));
            }
        } else {
            if (rc == SIGUSR1) {
                rotate_access = true;
                rotate_request = true;
                rotate_dstat = true;
            }
            if (rc == SIGTERM)
                ttg = true;
            if (rc == SIGHUP)
                gentlereload = true;

            DEBUG_debug("signal: ", String(rc));
            if (o.conn.logconerror) {
                E2LOGGER_info("ssigtimedwait() signal recd:", String(rc));
            }
        }
#endif   // end __OpenBSD__ else

        int q_size = o.http_worker_Q.size();
        DEBUG_debug("busychildren:", String(dystat->busychildren),
                    " worker Q size:", q_size);
        if (o.dstat.dstat_log_flag) {
            if (q_size > 10) {
                E2LOGGER_info("Warning: all ", o.proc.http_workers, " http_worker threads are busy and ",
                              q_size, " connections are waiting in the queue.");
            }
        } else {
            int busy_child = dystat->busychildren;
            if (busy_child > (o.proc.http_workers - 10))
                E2LOGGER_info("Warning system is full : max httpworkers: ", o.proc.http_workers, " Used: ",
                              busy_child);
        }

        //      if (is_starting)

        time_t now = time(NULL);


        if (o.dstat.dstat_log_flag && (now >= dystat->end_int))
            dystat->reset();
    }


    //  tidy-up

    sigfillset(&signal_set);
    pthread_sigmask(SIG_BLOCK, &signal_set, NULL);

    E2LOGGER_info("Stopping");

    if (o.monitor.monitor_flag_flag)
        monitor_flag_set(false);
    // if (o.monitor_helper_flag)
    //     tell_monitor(false); // tell monitor that we are not accepting any more connections

    if (o.conn.logconerror) {
        E2LOGGER_info("sending null socket to http_workers to stop them");
    }
    Socket *NS = NULL;
    LQ_rec rec;
    rec.sock = NS;
    rec.ct_type = CT_PROXY;
    for (i = 0; i < o.proc.http_workers; i++) {
        o.http_worker_Q.push(rec);
    }
    // dystat->reset();    // remove this line for production version

    //std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    //E2LOGGER_info("2nd wait complete");
    e2logger_ttg = true;
    std::string nullstr("");
    o.log.log_Q->push(nullstr);
    //if (o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        o.log.RQlog_Q->push(nullstr);
    }

    if (o.conn.logconerror) {
        E2LOGGER_info("stopping any remaining connections");
    }
    serversockets.self_connect();   // stop accepting connections
    if (o.conn.logconerror) {
        E2LOGGER_info("connections stopped");
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    if (o.dstat.dstat_log_flag) dystat->close();

    delete[] serversockfds;

    if (o.conn.logconerror) {
        E2LOGGER_info("Main thread exiting.");
    }
    return 0;
}
