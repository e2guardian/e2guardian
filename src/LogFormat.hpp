//
// Class for holding LogFormat
//
// Created by philip on 16 June 2023.
//

#ifndef LOGFORMAT_HPP
#define LOGFORMAT_HPP

#include <iostream>
#include <thread>
#include <deque>
#include "String.hpp"
#include "Logger.hpp"

class logf_item {
public:
        int code = 0;  // enum
        String name = ""; // name of item for most, but 'item:header_id:' for reqh and resh
        // this will be used in header log if add_header is true
        String header_name = ""; // HTTP header id i.e. 'header_id:'
    };



class LogFormat {
public:
    LogFormat();

    ~LogFormat();

    void reset();


    String delimiter;    // if set override the one set by output type
    bool add_header = false;
    bool use_dash_for_blanks = false;
    bool add_quotes_to_strings = false;

#undef X
#define FENUM \
        X(BLANK, "Blank"," empty column",true), \
        X(ACTIONWORD,"ActionWord"," actionWord(s) *DENIED*, *EXCEPTION, etc",true), \
        X(AUTHROUTE,"AuthRoute","How this has been authenticated ",true), \
        X(BSIZE,"BodySize"," size of body in bytes",false), \
        X(CATEGORY,"Category","Category",true),  \
        X(CLIENTHOST,"ClientHost","Client hostname",true),  \
        X(CLIENTHOSTORIP,"ClientHostOrIP"," client host (from reverse DNS) if unavailable the client IP",true), \
        X(CLIENTIP,"ClientIP"," was 'from' in log_listener",true), \
        X(DURATIONMS,"DurationMs"," time taken to service request in ms (= end_utime - start_utime)",false), \
        X(END_LTIME,"EndLtime"," end timestamp local time in human-readable format",true), \
        X(END_UTIME,"EndUtime"," end timestamp in utime format",false), \
        X(EXTFLAGS,"ExtFlags", "Extended Flags",true),  \
        X(GROUP_NAME,"GroupName", "Group Name",true),  \
        X(GROUP_NO,"GroupNo", "Group Number",false), \
        X(LISTENINGPORT,"ListenPort", "E2g port that accepted the connection",false), \
        X(LOGID_1,"LogId1","  Only used in log type 4 - but keep",true), \
        X(LOGID_2,"LogId2","  Only used in log type 4 - keep",true), \
        X(MESSAGE_NO,"MessageNo"," e2g message_no or 200 if OK",false), \
        X(MIMETYPE,"MimeType", "mime type",true),  \
        X(NAUGTHTINESS,"Naughtiness"," was sweight",false), \
        X(PRODUCTID,"ProductId","  Only used in log type 4 - keep",true), \
        X(PROXYIP,"ProxyIP"," Upstream proxy IP - was 'heir'",true), \
        X(PROXYSERVICE,"ProxyService","Type of proxy service flag - T= tranparent, P= explict proxy, M= MITM",true), \
        X(REQHEADER,"ReqHeader"," requestheader  ",true), \
        X(RESHEADER,"ResHeader"," response header",true), \
        X(RQTYPE,"ReqType"," request type ('GET' etc) was 'how'",true), \
        X(REQUESTID,"RequestId"," request ID - is thread_id + startUtime",true), \
        X(RSCODE,"ResCode","      response code",false), \
        X(SEARCHTERMS,"SearchTerms", "Search Terms",true),  \
        X(SERVER,"Server","Server name",true),  \
        X(START_LTIME,"StartLtime"," start timestamp local time in human-readable format",true), \
        X(START_UTIME,"StartUtime"," start timestamp unix time in secs since 1/1/1970",false), \
        X(THREADID,"ThreadId","Thread_id of the worker",true), \
        X(URL,"Url"," = full url - was 'where'",true), \
        X(USER,"User"," was 'who' in log_listener",true), \
        X(USERAGENT,"UserAgent"," replace with header spec???",true), \
        X(WHATISNAUGHTY,"WhatsNaughty","What is naughty",true), \
        X(WHAT_COMBI,"WhatCombi"," actionWord(s) + what_is_naughty - was 'what'",true), \
        X(TOP, "top", "top of array",false)

#define X(key, name, comment, isstring) key
    enum F : int {
        FENUM
    };
#undef X

#define X(key, name, comment, isstring) name
    String const labels[TOP + 1] =
            {
                    FENUM
            };
#undef X

#define X(key, name, comment, isstring) isstring
    bool const is_string[TOP + 1] =
            {
                    FENUM
            };
#undef X

#define LOGFORMATS \
X(LOG_FORMAT_CSV, "csv", "Comma separated values"), \
X(LOG_FORMAT_TSV, "tsv", "Tab separated values"), \
X(LOG_FORMAT_SSV, "ssv", "Space separated values"), \
X(LOG_FORMAT_TOP, "top", "top of array")

#define X(key, name, comment) key

    enum Formats : int {
        LOGFORMATS
    };

#undef X

#define X(key, name, comment) name

    String const format_labels[LOG_FORMAT_TOP + 1] =
            {
                    LOGFORMATS
            };


    int format_type = LOG_FORMAT_TSV;

    int get_key(String &name);

    int get_format_key(String &name);

    struct item {
        F code = BLANK;  // enum
        String name = ""; // name of item for most, but 'item:header_id:' for reqh and resh
        // this will be used in header log if add_header is true
        String header_name = ""; // HTTP header id i.e. 'header_id:'
    };


    std::vector<logf_item> item_list;

    int list_size();

    bool present[TOP];  // set present[F] to true if field output required

    std::vector<String> reqh_needed_list;  // list of request headers needed for log
    std::vector<String> resh_needed_list;   // list of response headers needed for log

    bool readfile(String &filename);
};


#endif //LOGFORMAT_HPP
