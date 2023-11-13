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
#include "LogTransfer.hpp"

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

    char outbuff[101];

    long cps = cnx / period;
    long rqs = rqx / period;
    if (o.dstat.stats_human_readable) {
        struct tm *timeinfo;
        time(&now);
        timeinfo = localtime(&now);
        char buffer[50];
        strftime(buffer, 50, "%Y-%m-%d %H:%M", timeinfo);
        snprintf(outbuff, 100, "%s	%d	%d	%d	%d	%ld	%ld	%ld	 %ld	%d	 %d", buffer,
                 o.proc.http_workers,
                 bc, o.http_worker_Q.size(), o.log.log_Q->size(), cnx, cps, rqx, rqs, mfd, LC);
    } else {
        snprintf(outbuff, 100, "%ld	%d	%d	%d	%d	%ld	%ld	%ld	%ld	%d	%d", now,
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
void log_listener(Queue<LogTransfer*> *log_Q, bool is_RQlog);

// fork off into background
bool daemonise();
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
bool daemonise() {
    if (o.proc.no_daemon) {
        return true;
    }
#ifdef DEBUG_LOW
    return true; // if debug mode is enabled we don't want to detach
#endif

    if (is_daemonised) {
        return true; // we are already daemonised so this must be a
        // reload caused by a HUP
    }

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

void log_listener(Queue<LogTransfer*> *log_Q, bool is_RQlog) {
    LogFormat *F;
    if (is_RQlog) {
        thread_id = "RQlog: ";
        F = &(o.log.request_log_format);
    } else {
        thread_id = "log: ";
        DEBUG_trace("item_list size is ",o.log.access_log_format.item_list.size());
        F = &(o.log.access_log_format);
    }
    DEBUG_trace("Type of format_type is ",F->format_type );
    DEBUG_trace("item_list size is ",F->item_list.size());

    try {
        DEBUG_trace("log listener ", thread_id, " started");

        //String where, what, how;
        std::string cr("\n");

        int port = 80;

        String server = o.net.server_name;

        std::string semiexception_word = o.language_list.getTranslation(51);
        semiexception_word = "*" + semiexception_word + "* ";
        std::string exception_word = o.language_list.getTranslation(51);
        exception_word = "*" + exception_word + "* ";
        std::string denied_word = o.language_list.getTranslation(52);
        denied_word = "*" + denied_word + "* ";
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

        if (F->use_dash_for_blanks)
            blank_str = "-";
        else
            blank_str = "";

        if(F->add_header) {
            String line;
            for (auto i = F->item_list.begin(); i < F->item_list.end(); i++) {
                if (i > F->item_list.begin()) {
                   line += F->delimiter;
                }
                if(F->add_quotes_to_strings) line += "\"";
                line += i->name;
                if(F->add_quotes_to_strings) line += "\"";
            }
            DEBUG_trace("Log line is ", line);
            if (is_RQlog) {
                E2LOGGER_requestlog(line);
            } else {
                E2LOGGER_accesslog(line);
                E2LOGGER_alertlog(line);
                E2LOGGER_responselog(line);  // Will only work if responselog is enabled.
            }
        }


        while (!e2logger_ttg) { // loop, essentially, for ever
            std::string loglines;
            LogTransfer *T = nullptr;

            T = log_Q->pop();  // get logdata from queue

            if (e2logger_ttg) break;
            if (is_RQlog && rotate_request) {
                e2logger.rotate(LoggerSource::requestlog);
                rotate_request = false;
            } else if (!is_RQlog && rotate_access) {
                e2logger.rotate(LoggerSource::accesslog);
                rotate_access = false;
            }
            DEBUG_debug("received a log request");
            DEBUG_trace("Got log record from ", T->thread_id ," via Q");

            std::shared_ptr <LOptionContainer> ldl;
            ldl = o.currentLists();

            // Start building the log line

                    String full_url = T->url;

            if (port != 0 && port != 80) {
                // put port numbers of non-standard HTTP requests into the logged URL
                String newwhere(T->url);
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
                    newwhere += String((int) T->port);
                    newwhere += "/";
                    newwhere += path;
                    full_url = newwhere;
                } else {
                    full_url += ":";
                    full_url += String((int) port);
                }
            } else {
                full_url = T->url;
            }
            DEBUG_trace("Full_url is ",full_url);

            String groupname;
            String stringcode(T->rscode);

            if (is_RQlog && !T->is_authed) {
                groupname = "";
            } else {
                if (stringcode == "407" && groupname.empty()) {
                    groupname = "negotiate_identification";
                } else {
                    groupname = ldl->fg[T->filtergroup]->name;
                }
            }

            // Make our output line using format

            std::string builtline, year, month, day, hour, min, sec, when, vbody, utime;
            std::string quotes;
            long durationsecs, durationusecs;
	    String section;
	    String temp1, temp2, temp3;
            char date[32];
            struct tm tm, *ptm;
	    DEBUG_trace("Log record do_access_log is ",T->do_access_log);
DEBUG_trace("Building log line..." );
            for (auto i = F->item_list.begin(); i < F->item_list.end(); i++) {
                if (i > F->item_list.begin()) {
                    builtline += F->delimiter;
                };
                section.clear();
                String what;
                switch(i->code) {
                    case LogFormat::WHAT_COMBI:
                        what = T->what_is_naughty;
                    case LogFormat::ACTIONWORD:
                        if (T->is_naughty) {
                            if (T->upfailure)
                                section += neterr_word;
                            else
                                section += denied_word;
                        } else if (T->is_exception) {
                            if (T->is_semi_exception) {
                                section += semiexception_word;
                            } else {
                                section += exception_word;
                            }
                        }
                        if (T->was_infected)
                            section += infected_word;
                        else if (T->was_scanned)
                            section += scanned_word;
                        if (T->content_modified) {
                            section += contentmod_word;
                        }
                        if (T->url_modified) {
                            section += urlmod_word;
                        }
                        if (T->header_modified) {
                            section += headermod_word;
                        }
                        if (T->header_added) {
                            section += headeradd_word;
                        }
                        section += what;
                        break;
                    case LogFormat::AUTHROUTE:
                        section = T->extflags.after(":").after(":");
                        break;
                    case LogFormat::BSIZE:
                        temp1 = T->docsize;
                        section += temp1;
                        break;
                    case LogFormat::CATEGORY:
                        section += T->categories;
                        break;
                    case LogFormat::CLIENTHOST:
                        section += T->clientHost;
                        break;
                    case LogFormat::CLIENTHOSTORIP:
                        if (T->clientHost.empty()) {
                            section += T->client_ip;
                        } else {
                            section += T->clientHost;
                        }
                        break;
                    case LogFormat::CLIENTIP:
                        section += T->client_ip;
                        break;
                    case LogFormat::DURATIONMS:
                        durationsecs = (T->end_time.tv_sec - T->start_time.tv_sec);
                        durationusecs = T->end_time.tv_usec - T->start_time.tv_usec;
                        durationusecs = (durationusecs / 1000) + durationsecs * 1000;
                        temp1 = durationusecs;
                        section += temp1;
                        break;
                    case LogFormat::END_LTIME:
                        ptm = localtime_r(&T->end_time.tv_sec, &tm);
                        strftime(date, sizeof date, "%Y.%m.%d %H:%M:%S", ptm);
                        section = date;
                        break;
                    case LogFormat::END_UTIME:
                        temp2 = T->end_time.tv_usec / 1000;
                        temp3 = T->end_time.tv_sec;
                        if (temp2.length() < 3) {
                            temp2.insert(0, 3 - temp2.length(), '0');  // pad to 3 digits
                        }
                        temp2.insert(0, 1 , '.');
                        section += temp3;
                        section += temp2;
                        break;
                    case LogFormat::EXTFLAGS:
                        section += T->extflags;
                        break;
                    case LogFormat::GROUP_NAME:
                        section += groupname;
                        break;
                    case LogFormat::GROUP_NO:
                        temp1 = T->filtergroup;
                        section += temp1;
                        break;
                    case LogFormat::LISTENINGPORT:
                        section = T->extflags.before(":");
                        break;
                    case LogFormat::LOGID_1:
                        section += o.log.logid_1;
                        break;
                    case LogFormat::LOGID_2:
                        section += o.log.logid_2;
                        break;
                    case LogFormat::MESSAGE_NO:
                        section += T->message_no;
                        break;
                    case LogFormat::MIMETYPE:
                        section += T->mime_type;
                        break;
                    case LogFormat::NAUGTHTINESS:
                        temp1 = T->naughtiness;
                        section += temp1;
                        break;
                    case LogFormat::PRODUCTID:
                        section += o.log.prod_id;
                        break;
                    case LogFormat::PROXYIP:
                        section += o.net.proxy_ip;
                        break;
                    case LogFormat::PROXYSERVICE:
                        section = T->extflags.after(":").before(":");
                        break;
                    case LogFormat::REQUESTID:
                        section += T->request_id;
                        break;
                    case LogFormat::RQTYPE:
                        section += T->rqtype;
                        break;
                    case LogFormat::RSCODE:
                        temp1 = T->rscode;
                        section += temp1;
                        break;
                    case LogFormat::SEARCHTERMS:
                        section += T->search_terms;
                        break;
                    case LogFormat::SERVER:
                        section += server;
                        break;
                    case LogFormat::START_LTIME:
                        ptm = localtime_r(&T->start_time.tv_sec, &tm);
                        strftime(date, sizeof date, "%Y.%m.%d %H:%M:%S", ptm);
                        section = date;
                        break;
                    case LogFormat::START_UTIME:
                        temp2 = T->start_time.tv_usec / 1000;
                        temp3 = T->start_time.tv_sec;
                        if (temp2.length() < 3) {
                            temp2.insert(0, 3 - temp2.length(), '0');  // pad to 3 digits
                        }
                        temp2.insert(0, 1 , '.');
                        section += temp3;
                        section += temp2;
                        break;
                    case LogFormat::THREADID:
                        section += T->thread_id;
                        break;
                    case LogFormat::URL:
                        section += full_url;
                        break;
                    case LogFormat::USER:
                        section += T->user;
                        break;
                    case LogFormat::USERAGENT:
                        section += T->useragent;
                        break;
                    case LogFormat::REQHEADER:
                        for (auto p : T->reqh_needed_list) {
                            if (p.startsWithLower(i->header_name)) {
                                section = p.after(":");
                                break;
                            }
                        }
                            break;
                    case LogFormat::RESHEADER:
                        for (auto p : T->resh_needed_list) {
                            if (p.startsWithLower(i->header_name)) {
                                section = p.after(":");
                                break;
                            }
                            break;
                        }
                    default:
                        E2LOGGER_error("Internal error - storage for field code ",i->code, " not defined");
                        section = "";
                        break;
                }
                DEBUG_trace("Log section is after switch", section);
                if (F->use_dash_for_blanks && section.empty())   // numerics will never be empty so we don't need to test if string field
                    section = "-";
                if( F->add_quotes_to_strings && F->is_string[i->code]) {
                    section.insert(0,1,'"');
                    section.append("\"");
                }
                builtline += section;

            }


            // Send to Log
            DEBUG_trace("Now sending to Log");
            DEBUG_trace("Log line is ", builtline);
            if (is_RQlog) {
                E2LOGGER_requestlog(builtline);
            } else {
                if(T->do_access_log) {
                    E2LOGGER_accesslog(builtline);
                }
                if(T->do_alert_log) {
                    E2LOGGER_alertlog(builtline);
                }
                E2LOGGER_responselog(builtline);  // Will only work if responselog is enabled.
            }

            if(T != nullptr)
                delete T;

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

    if (!daemonise()) {
        // detached daemon
        E2LOGGER_error("Error daemonising");
        close(pidfilefd);
        delete[] serversockfds;
        return 1;
    }

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

    // this has to be done after daemonise to ensure we get the correct PID.
    rc = sysv_writepidfile(pidfilefd); // also closes the fd
    if (rc != 0) {
        E2LOGGER_error("Error writing to the e2guardian.pid file: ", strerror(errno));
        delete[] serversockfds;
        return false;
    }
    // We are now a daemon so all errors need to go in the syslog, rather
    // than being reported on screen as we've detached from the console and
    // trying to write to stdout will not be nice.

    g_is_starting = false;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    // Now start creating threads so main thread can just handle signals, list reloads and stats
    // This removes need for select and/or epoll greatly simplifying the code
    // Threads are created for logger, a separate thread for each listening port
    // and an array of worker threads to deal with the work.
    //if (!o.no_logger) {

   // if (e2logger.isEnabled(LoggerSource::responselog)) {
   //     std::thread RSlog_thread(log_listener, o.log.RSlog_Q, false, true, false);
   //     RSlog_thread.detach();
   //     DEBUG_trace("RSlog_listener thread created");
   // }
   // if (e2logger.isEnabled(LoggerSource::alertlog)) {
   //     std::thread ALlog_thread(log_listener, o.log.ALlog_Q, false, false, true);
   //     ALlog_thread.detach();
   //     DEBUG_trace("ALlog_listener thread created");
   // }

    // I am the main thread here onwards.
    DEBUG_trace("Master thread created threads");

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

    if (e2logger.isEnabled(LoggerSource::accesslog)) {
    DEBUG_trace("item_list before tread start is ", o.log.access_log_format.item_list.size());
        std::thread log_thread(log_listener, o.log.log_Q, false);
        log_thread.detach();
        DEBUG_trace("log_listener thread created");
    }

    //if(o.log_requests)
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        std::thread RQlog_thread(log_listener, o.log.RQlog_Q, true);
        RQlog_thread.detach();
        DEBUG_trace("RQlog_listener thread created");
    }

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
        dystat->start();
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

                    DEBUG_debug("signal:", String(rc);
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
    o.log.log_Q->push(nullptr);
    //if (o.log_requests)
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        o.log.RQlog_Q->push(nullptr);
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
