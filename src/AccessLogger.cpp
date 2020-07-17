// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "AccessLogger.hpp"
#include "Logger.hpp"
#include "OptionContainer.hpp"
#include "ConnectionHandler.hpp"

#include <ctime>
#include <csignal>
#include <sys/time.h>

// GLOBALS
extern OptionContainer o;

namespace AccessLogger {

// GLOBALS
std::atomic<bool> e2logger_ttg;

void shutDown()
{
    e2logger_ttg = true;
}

struct LogRecord::Helper 
{
    static String getWhere(String where, unsigned int port)
    {
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
            } else {
                newwhere = where += ":" + String((int) port);
            }
            return newwhere;
        } else {
            return where;
        }
    }

    static String getTimestamp(const timeval &time)
    {
        String temp((int) ( time.tv_usec / 1000));
        while (temp.length() < 3) {
            temp = "0" + temp;
        }
        if (temp.length() > 3) {
            temp = "999";
        }
        return String((int) time.tv_sec) + "." + temp;
    }

    static String getDateTime(const timeval &time)
    {
            time_t now = time.tv_sec;
            char date[32];
            struct tm *tm = localtime(&now);
            strftime(date, sizeof date, "%Y.%m.%d %H:%M:%S", tm);
            return String(date);
    }

    static String getDuration(const timeval &thestart, const timeval &theend)
    {
        long durationsecs, durationusecs;
        durationsecs = (theend.tv_sec - thestart.tv_sec);
        durationusecs = (theend.tv_usec - thestart.tv_usec);
        durationusecs = (durationusecs / 1000) + durationsecs * 1000;
        String duration((int) durationusecs);
        return duration;
    }

    static String getGroupname(const int code, const String filtergroupname)
    {
        if (code == 407) {
            return "negotiate_identification";
        } else {
            return filtergroupname;
        }        
    }

    static String getHitMiss(const int code, bool cachehit)
    {
        if (code == 403) {
            return "TCP_DENIED/403";
        } else {
            if (cachehit) {
                return String("TCP_HIT/") + String(code);
            } else {
                return String("TCP_MISS/") + String(code);
            }
        }
    }


}; // struct LogRecord::Helper

void doLog(std::string &who, std::string &from, NaughtyFilter &cm, 
        std::list<AccessLogger::postinfo> *postparts, 
        std::string urlparams) {

    e2logger_trace("who: ", who, " from: ", from );

    bool is_real_user; // ??

    struct timeval theend;
    gettimeofday(&theend, NULL);

    String where = cm.logurl;
    String cat = cm.whatIsNaughtyCategories;
    String what = cm.whatIsNaughtyLog;

    HTTPHeader *reqheader = cm.request_header;

    // if(o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::debugrequest)) {
        what = thread_id + what;
    }

    // don't log if logging disabled entirely, or if it's an ad block and ad logging is disabled,
    // or if it's an exception and exception logging is disabled
    if (o.ll == 0) return;
    if (!o.log_ad_blocks) {
        if ( strstr(cat.c_str(), "ADs") != NULL ) {
            e2logger_debug(" -Not logging 'ADs' blocks");
            return;
        }
    }
    if ((o.log_exception_hits == 0) && cm.isException) {
        e2logger_debug(" -Not logging exceptions");               
        return;
    }

    if ((cm.isException && (o.log_exception_hits == 2))
        || cm.isItNaughty 
        || o.ll == 3 
        || (o.ll == 2 && cm.is_text)) {

        // put client hostname in log if enabled.
        // for banned & exception IP/hostname matches, we want to output exactly what was matched against,
        // be it hostname or IP - therefore only do lookups here when we don't already have a cached hostname,
        // and we don't have a straight IP match agaisnt the banned or exception IP lists.
        if (o.log_client_hostnames && (cm.clienthost == "") && !cm.anon_log) {

            e2logger_debug("logclienthostnames enabled but reverseclientiplookups disabled; lookup forced.");
            getClientFromIP(from.c_str(), cm.clienthost);
            //std::deque<String> *names = ipToHostname(from.c_str());
            //if (names->size() > 0) {
                //clienthost = new std::string(names->front().toCharArray());
                //cm.clienthost = *clienthost;
            //}
            //delete names;
        }

        // Build up string describing POST data parts, if any
        std::ostringstream postdata;
        for (std::list<postinfo>::iterator i = postparts->begin(); i != postparts->end(); ++i) {
            // Replace characters which would break log format with underscores
            std::string::size_type loc = 0;
            while ((loc = i->filename.find_first_of(",;\t ", loc)) != std::string::npos)
                i->filename[loc] = '_';
            // Build up contents of log column
            postdata << i->mimetype << "," << i->filename << "," << i->size
                     << "," << i->blocked << "," << i->storedname << "," << i->bodyoffset << ";";
        }
        postdata << std::flush;


        // Item length limit put back to avoid log listener
        // overload with very long urls Philip Pearce Jan 2014
        if (cat.length() > o.max_logitem_length)
            cat.resize(o.max_logitem_length);
        if (what.length() > o.max_logitem_length)
            what.resize(o.max_logitem_length);
        if (where.length() > o.max_logitem_length)
            where.limitLength(o.max_logitem_length);

        // if (o.dns_user_logging && !is_real_user) {
        //     String user;
        //     if ( ConnectionHandler::getdnstxt(from, user)) {
        //         who = who + ":" + user;
        //         // What is this used for ??
        //         //SBauth.user_name = user;
        //         //SBauth.user_source = "dnslog";
        //     };
        //     is_real_user = true;    // avoid looping on persistent connections
        // };

        e2logger_debug(" -Building log data record... ");
        AccessLogger::LogRecord *logrec = new LogRecord;
        logrec->where = where;
        logrec->what = what;
        logrec->how = cm.request_header->requestType();;
        logrec->who = who;
        logrec->from = from;
        logrec->category = cat;
        logrec->isexception = cm.isexception;
        logrec->isnaughty = cm.isItNaughty;
        logrec->naughtytype = cm.blocktype;
        logrec->naughtiness = cm.naughtiness;
        logrec->port = cm.request_header->port;;
        logrec->wasscanned = cm.wasscanned;
        logrec->wasinfected = cm.wasinfected;
        logrec->contentmodified = cm.contentmodified;;
        logrec->urlmodified = cm.urlmodified;
        logrec->headermodified = cm.headermodified;
        logrec->headeradded = cm.headeradded;
        logrec->size = cm.docsize;;
        logrec->filtergroup = cm.filtergroup;
        logrec->filtergroupname = cm.filtergroup;
        logrec->code = (cm.response_header->returnCode());
        if (cm.isItNaughty) logrec->code = 403;

        logrec->cachehit = false; // ?? cachehit;
        logrec->mimetype = cm.mimetype;
        logrec->thestart = cm.thestart;
        logrec->theend = theend;
        logrec->clientip = cm.clienthost;
        logrec->clienthost = cm.clienthost;
        if (o.log_user_agent)
          logrec->useragent = (reqheader ? reqheader->userAgent() : "" );
        logrec->postdata = postdata.str();
        logrec->message_no = cm.message_no;;
        logrec->flags = cm.getFlags();
        logrec->urlparams = urlparams;
        logrec->search_terms = cm.search_terms;

        if (cm.anon_log) {
            logrec->who = "";
            logrec->from = "0.0.0.0";
            logrec->clienthost = "";
        }

        e2logger_debug(" -...built");

        // push on log queue
        o.log.log_Q.push(logrec);
    }
}

void doRQLog(std::string &who, std::string &from, NaughtyFilter &cm, std::string &funct) {
}

void log_listener(Queue<LogRecord*> &log_Q, bool is_RQlog)
{
    if (is_RQlog)
        thread_id = "RQlog: ";
    else
        thread_id = "log: ";

    try {
        e2logger_trace("log listener started");

#ifdef ENABLE_EMAIL
    // Email notification patch by J. Gauthier
    std::map<std::string, int> violation_map;
    std::map<std::string, int> timestamp_map;
    std::map<std::string, std::string> vbody_map;

    int curv_tmp, stamp_tmp, byuser;
#endif


    // std::string where, what, how, cat, clienthost, from, who, mimetype, useragent, ssize, sweight, params, message_no;
    // std::string stype, postdata, flags, searchterms;
    // int port = 80, isnaughty = 0, isexception = 0, code = 200, naughtytype = 0;
    // int cachehit = 0, wasinfected = 0, wasscanned = 0, filtergroup = 0;
    // long tv_sec = 0, tv_usec = 0, endtv_sec = 0, endtv_usec = 0;
    // int contentmodified = 0, urlmodified = 0, headermodified = 0;
    // int headeradded = 0;

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

    while (!e2logger_ttg) { // loop, essentially, for ever
        LogRecord *log_rec;
        log_rec = log_Q.pop();
        if (log_rec == NULL) break;
        if (e2logger_ttg) break;
        e2logger_debug("received a log request");

        // Start building the log line

#ifdef TODO

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

#endif

        String builtline;
        switch (o.log_file_format) {
            case 1:
                builtline = log_rec->getFormat1();
                break;
            case 2:
                builtline = log_rec->getFormat2();
                break;
            case 3:
                builtline = log_rec->getFormat3();
                break;
            case 4:
                builtline = log_rec->getFormat4();
                break;
            case 5:
            case 6:
                builtline = log_rec->getFormat5();
                break;
            case 7:
            case 8:
            default:
                builtline = log_rec->getFormat7();
                break;
        }

        delete log_rec; log_rec = NULL;

        // Send to Log
        e2logger_trace("Now sending to Log");
        if (is_RQlog) {
            e2logger_debugrequest(builtline);
        } else {
            e2logger_access(builtline);
        }


#ifdef TODO_ENABLE_EMAIL
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
                            e2logger_error("Unable to contact defined mailer.");
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
                                    e2logger_error("Unable to contact defined mailer.");
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
    if( !e2logger_ttg)
        e2logger_debug("log_listener exiting with error");

    } catch (...) {
        e2logger_error("log_listener caught unexpected exception - exiting");
    }

    if (!e2logger_ttg)
        e2logger_error("log_listener exiting with error");
    else if (o.logconerror)
        e2logger_error("log_listener exiting");

    return; // It is only possible to reach here with an error
}


String LogRecord::getPart(const std::string part)
{
    if (part == "when")         return Helper::getDateTime(theend);
    if (part == "timestamp")    return Helper::getTimestamp(theend);
    if (part == "datetime")     return Helper::getDateTime(theend);
    if (part == "duration")     return Helper::getDuration(thestart, theend);

    if (part == "who")          return ( o.anonymise_logs ? "" : who);
    if (part == "from")         return ( o.anonymise_logs ? "0.0.0.0" : from);
    if (part == "where")        return Helper::getWhere(where, port);
    if (part == "what")         return what;
    if (part == "how")          return how;
    if (part == "code")         return std::to_string(code);
    if (part == "server")       return o.server_name;
    if (part == "useragent")    return ( o.log_user_agent ? useragent : "");
    if (part == "params")       return urlparams;
    
    if (part == "filtergroup")  return String(filtergroup);
    if (part == "groupname")    return Helper::getGroupname(code, filtergroupname);
    if (part == "clientip")     return ( o.anonymise_logs ? "" : clientip);
    if (part == "clienthost")   return ( o.anonymise_logs ? "" : clienthost);

    if (part == "postdata")     return postdata;
    if (part == "category")     return category;
    if (part == "size")         return String(size);
    if (part == "mimetype")     return mimetype;
    if (part == "hitmiss")      return Helper::getHitMiss(code, cachehit);
    if (part == "hier")         return String("DEFAULT_PARENT/") + String(o.proxy_ip);

    if (part == "squid_result_code") return ""; // ???
    if (part == "squid_peer_code")   return ""; // ???

    return String("N/A(" + part + ")" );
}

String LogRecord::getFormatted(const std::string format, const char delimiter)
{
    std::vector<std::string> tokens = String(format).split(' ');
    String result;

    for (auto const &s: tokens) {
        String part = this->getPart(s);
        result = result + part + String(delimiter);
    }
    result.chop();
    return result;
}

#define FORMAT_DG       "when who from where  what how  size weight category filtergroup " \
                        "code mimetype clienthost groupname useragent params logid1 logid2 " \
                        "postdata"
#define FORMAT_SQUID    "timestamp duration clienthost hitmiss size how where who hier mimetype"
#define FORMAT_PROTEX   "timestamp server who from clienthost where how code size mimetype " \
                        "useragent  squid_result_code duration squid_peer_code " \
                        "message_no what weight category groupname filtergroup"

String LogRecord::getFormat1()
{
    String format = String(FORMAT_DG);
    String formatted = this->getFormatted(format, ' ');
    return formatted;
}

String LogRecord::getFormat2()
{
    String format = String(FORMAT_DG);
    String formatted = this->getFormatted(format, ',');
    return formatted;
}
String LogRecord::getFormat3()
{
    String format = String(FORMAT_SQUID);
    String formatted = this->getFormatted(format, ',');
    return formatted;
}

String LogRecord::getFormat4()
{
    String format = String(FORMAT_DG);
    String formatted = this->getFormatted(format, '\t');
    return formatted;
}

String LogRecord::getFormat5()
{
    String format = String(FORMAT_PROTEX);
    String formatted = this->getFormatted(format, '\t');
    return formatted;

}

String LogRecord::getFormat7()
{
    String format = String(FORMAT_PROTEX) + "searchterms flags";
    String formatted = this->getFormatted(format, '\t');
    return formatted;

}

} // namespace AccessLogger
