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
        utime,
        server,
        user,      // was 'who'
        clientip,
        clientHost,
        clientHostOrIp,
        where,   // = full url
        rtype,        // request type ('GET' etc) was 'how'
        rcode,   // from response ???
        ssize,
        mimetype,
        useragent,  // replace with header spec???
        durationms,
        message_no,
        what,       // ???
        sweight,     // ??
        category,
        groupName,
        groupNo,
        searchTerms,
        flags,
        params,   // ??
        logid_1,  // ??
        logid_2,  // ??
        postdata,  // ??
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
