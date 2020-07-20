// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_DSTAT
#define __HPP_DSTAT

#include <atomic>
#include <ctime>
#include <stdio.h>

// DEFINITIONS
class DStat
{
    public:
    void reset();
    void start();
    void clear();
    void close();

    void connectionAccepted() { ++busychildrens; ++conx; }
    void connectionClosed() { --busychildrens; }
    void requestAccepted() { ++reqs; }
    void busychildrenReset() { busychildrens = 0; }
    void filedescriptorUsed(int fd) { if (fd > maxusedfd) maxusedfd = fd; }

    void timetick();        // call this regularly so that DStat could detect a new interval

    const int busychildren() { return busychildrens; }

    private:
    long births = 0;        // num of child forks in stat interval
    long deaths = 0;        // num of child deaths in stat interval
    std::atomic<int> conx ; // num of client connections in stat interval
    std::atomic<int> reqs;  // num of client requests in stat interval
    time_t start_int;       // time of start of this stat interval
    time_t end_int;         // target end time of stat interval
    std::atomic<int> maxusedfd;     // max fd reached
    std::atomic<int> busychildrens; 
    FILE *fs; // file stream

};

// GLOBALS 
extern DStat dstat;

#endif