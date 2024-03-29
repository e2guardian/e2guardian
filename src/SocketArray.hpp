// SocketArray - wrapper for clean handling of an array of Sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_SOCKETARRAY
#define __HPP_SOCKETARRAY

// INCLUDES
#include "Socket.hpp"
#include "String.hpp"

#include <deque>
#include<thread>
#include <vector>

// DECLARATIONS

class SocketArray
{
    public:
    // set sensible defaults
    SocketArray()
        : drawer(NULL), socknum(0){};
    // delete all sockets
    ~SocketArray();

    // close all old socks & create specified amount of new ones
    void reset(int sockcount);

    // just delete the lot of 'em
    void deleteAll();

    // bind our sockets to the given IPs
    int bindAll(std::deque<String> &ips, std::deque<String> &ports, int &index, int ct_type);
    // bind just the one, to all available IPs
    int bindSingle(int port);
    int bindSingle(unsigned int index, int port, unsigned int CT_type);
    int bindSingleM(std::deque<String> &port, int &index, int ct_type);
    // set all sockets listening with given kernel queue length
    int listenAll(int queue);

    // shove all socket FDs into the given array (pass in unallocated)
    int *getFDAll();

    unsigned int getType(unsigned int ind);

    // try connecting to all our sockets which are still open to allow tidy close
    void self_connect();

    // array dereference operator
    Socket *operator[](int i)
    {
        return &(drawer[i]);
    };

    private:
    // our sock collection container
    Socket *drawer;
    std::vector<unsigned int> lc_types;   // holds listening connection type i.e. LC_PROXY, LC_THTTPS, LC_ICAP
    // how many sockets we have
    unsigned int socknum;
};

#endif
