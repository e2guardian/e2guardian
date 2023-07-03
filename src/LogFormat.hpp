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


#endif //LOGFORMAT_HPP

class LogFormat {
    String output_type = "tsv";  //can be 'csv' or 'tsv' currently
    bool add_header = false;
    bool use_dash_for_blanks = false;
    enum F {
        blank,          // empty column
        end_utime,      // end timestamp unix time in secs since 1/1/1970 - was 'when' in log_listener
        end_ltime,      // end timestamp local time in human-readable format
        server,
        user,      // was 'who' in log_listener
        clientip,  // was 'from' in log_listener
        clientHost,
        clientHostOrIp,  // client host (from reverse DNS) if unavailable the client IP
        url,   // = full url - was 'where'
        rqtype,        // request type ('GET' etc) was 'how'
        rscode,   //      response code
        ssize,      // size of body in bytes
        mimetype,
        useragent,  // replace with header spec???
        durationms, // time taken to service request in ms (= end_utime - start_utime)
        message_no, // e2g message_no or 200 if OK
        whatCombi,       // actionWord(s) + what_is_naughty - was 'what'
        actionWord,     // actionWord(s) *DENIED*, *EXCEPTION, etc
        whats_naughty,  //
        mimetype,
        naughtiness,     // was sweight
        category,
        groupName,
        groupNo,
        searchTerms,
        start_utime,  // start timestamp unix time in secs since 1/1/1970
        start_ltime,    // start timestamp local time in human-readable format
        extflags,
        params,   // ??  does not seem to do anything - remove
        logid_1,  //  Only used in log type 4 - but keep
        logid_2,  //  Only used in log type 4 - keep
        postdata,  // ??  Not implimented in v5 so far
        proxyIp,       // Upstream proxy IP - was 'heir'
        reqh,    // request header  - not sure if needed here as special case
        resh,    // response header  - not sure if needed here as special case
    };
    struct item {
        F code = blank;  // enum
        String name = ""; // name of item for most, but 'item:header_id:' for reqh and resh
                // this will be used in header log if add_header is true
        String header_name = ""; // HTTP header id i.e. 'header_id:'
    };
    std::deque<item> item_list;
};
