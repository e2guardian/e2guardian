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
        blank,
        endutime,      // unix time in secs since 1/1/1970
        endltime,      // local time in human-readable format
        server,
        user,      // was 'who' in log_listener
        clientip,  // was 'from' in log_listener
        clientHost,
        clientHostOrIp,
        where,   // = full url
        rtype,        // request type ('GET' etc) was 'how'
        rcode,   // from response ???
        ssize,
        mimetype,
        useragent,  // replace with header spec???
        durationms, // time taken to service request
        message_no,
        what,       // actionWord(s) + what_is_naughty
        mimetype,
        naughtiness,     // was sweight
        category,
        groupName,
        groupNo,
        searchTerms,
        start_utime,  // tv_sec
        start_ltime,  // tv_sec
        extflags,
        params,   // ??  does not seem to do anything - remove
        logid_1,  // ?? Only used in log type 4
        logid_2,  // ?? Only used in log type 4
        postdata,  // ??  Not implimented in v5 so far
        proxyIp,       // Upstream proxy IP - was 'heir'
        reqh,    // request header  - not sure if needed here as special case
        resh,    // response header  - not sure if needed here as special case
    };
    struct item {
        F code = blank;
        String name = "";
        String header_name = "";
    };
    std::deque<item> item_list;
};
