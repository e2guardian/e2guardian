//
// Class for transfering Log details from https worker via queue to log_listener thread.
//
// NB: To be tread safe a values must be copied - i.e. No pointers may be transferred as the objects reference may not exist
// when referenced by log_listener thread = Seg fallure.
//
// Created by philip on 18 July 2023.
//

#ifndef LOGTRANSFER_HPP
#define LOGTRANSFER_HPP

#include <iostream>
#include <thread>
#include <deque>
#include "String.hpp"
#include "LogFormat.hpp"



class LogTransfer {
public:
    LogTransfer();
    ~LogTransfer();
    void reset();

    // Time values - always transfered

    struct timeval start_time;
    struct timeval end_time;

    // Request type / Response code / e2g message code - always transfered
            String rqtype, rscode,  message_no;

            // relevant flags - exception blocked etc

    bool is_exception = false;
    bool upfailure = false;
    bool is_semi_exception = false;
    bool is_gray = false;
    bool is_naughty  = false;
    bool is_authed = false;

    bool was_infected = false;
    bool was_scanned = false;
    bool content_modified = false;
    bool url_modified = false;
    bool header_modified = false;
    bool header_added = false;
    bool is_text = false;        // is this needed??
    bool do_access_log = false;
    bool do_alert_log = false;

    off_t docsize = 0;
    int naughty_type = 0;
    int naughtiness = 0;
    int filtergroup = 0;
    int block_type = 0;

    String thread_id;
    String request_id;
    String what_is_naughty;
    String user;
    String useragent;
    String client_ip;
    String proxy_ip;
    String extflags;

    String url;
    int port = 0;


    // items that may not be required -to conserve stack usage only transfer if needed

    String mime_type;
    String categories;
    String clientHost;
    String search_terms;






    struct item {
        LogFormat::F code = LogFormat::BLANK;  // enum
        String name = ""; // name of item for most, but 'item:header_id:' for reqh and resh
                // this will be used in header log if add_header is true
        String header_name = ""; // HTTP header id i.e. 'header_id:'
    };


    std::deque<item> item_list;

    bool present[LogFormat::TOP];  // set present[F] to true if field output required

    std::vector<String> reqh_needed_list;  // list of request headers needed for log
    std::vector<String> resh_needed_list;   // list of response headers needed for log

};

#endif //LOGTRANSFER_HPP
