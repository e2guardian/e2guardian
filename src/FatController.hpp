// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_FATCONTROLLER
#define __HPP_FATCONTROLLER

// INCLUDES

#include "OptionContainer.hpp"
#include "UDSocket.hpp"

#include <string>
#include <atomic>

// DECLARATIONS

// program main loop - pass in FD of pidfile
int fc_controlit();

struct stat_rec {
    long births; // num of child forks in stat interval
    long deaths; // num of child deaths in stat interval
    std::atomic<int> conx ; // num of client connections in stat interval
    std::atomic<int> reqs; // num of client requests in stat interval
    time_t start_int; // time of start of this stat interval
    time_t end_int; // target end time of stat interval
    std::atomic<int> maxusedfd; // max fd reached
    std::atomic<int> busychildren; 
    FILE *fs; // file stream
    void reset();
    void start();
    void clear();
    void close();
};


#endif
