// SocketArray - wrapper for clean handling of an array of Sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "SocketArray.hpp"
#include "Queue.hpp"
#include "Logger.hpp"

#include <cerrno>
#include <cstring>

// GLOBALS


// IMPLEMENTATION

SocketArray::~SocketArray()
{
    delete[] drawer;
}

void SocketArray::deleteAll()
{
    delete[] drawer;
    drawer = NULL;
    socknum = 0;
}

// close all sockets & create new ones
void SocketArray::reset(int sockcount)
{
    delete[] drawer;

    drawer = new Socket[sockcount];
    socknum = sockcount;
}

// bind our first socket to any IP
int SocketArray::bindSingle(int port)
{
    if (socknum < 1) {
        return -1;
    }
    DEBUG_debug("bindSingle binding port", port);
    lc_types.push_back(CT_PROXY);
    return drawer[0].bind(port);
}

int SocketArray::bindSingle(unsigned int index, int port, unsigned int type)
{
    if (socknum <= index) {
        return -1;
    }
    DEBUG_debug("bindSingle binding port", port, " with type ", type);
    lc_types.push_back(type);
    return drawer[index].bind(port);
}


// bind our first socket to any IP and one or more ports
int SocketArray::bindSingleM(std::deque<String> &ports, int &index, int ct_type )
{
    if ( socknum < (index + ports.size())) {
        return -1;
    }
    for (auto i : ports) {
        DEBUG_debug("bindSingleM binding port", i);
        if (drawer[index].bind(i.toInteger())) {
            E2LOGGER_error("Error binding server socket: [", i, " ", index, "] (", strerror(errno), ")");
            return -1;
        }
        lc_types.push_back(ct_type);
        index++;
    }
    return 0;
}

// return an array of our socket FDs
int *SocketArray::getFDAll()
{
    int *fds = new int[socknum];
    for (unsigned int i = 0; i < socknum; i++) {
        DEBUG_debug("Socket ", i, " fd:", drawer[i].getFD() );
        fds[i] = drawer[i].getFD();
    }
    return fds;
}

// listen on all IPs with given kernel queue size
int SocketArray::listenAll(int queue)
{
    for (unsigned int i = 0; i < socknum; i++) {
        if (drawer[i].listen(queue)) {
            E2LOGGER_error("Error listening to socket");
            return -1;
        }
    }
    return 0;
}

// bind all sockets to given IP list
int SocketArray::bindAll(std::deque<String> &ips, std::deque<String> &ports, int &index, int ct_type)
{
    if ((index + (ips.size() * ports.size())) > socknum) {
        return -1;
    }
    //for (unsigned int i = 0; i < socknum; i++) {
    for (auto i_ips : ips) {
        for (auto i_ports : ports) {
            DEBUG_debug("Binding server socket[", i_ports, " ", i_ips, " ", index, "]");
            if (drawer[index].bind(i_ips.toCharArray(), i_ports.toInteger())) {
                E2LOGGER_error("Error binding server socket: [", i_ports, " ", i_ips, " ", index, "] (", strerror(errno),
                               ")");
                return -1;
            }
            lc_types.push_back(ct_type);
            index++;
        }
    }
    return 0;
}

// try connecting to all our sockets which are still open to allow tidy close
void SocketArray::self_connect() {
    for (unsigned int i = 0; i < socknum; i++) {
        if (drawer[i].getFD() > -1) {
            std::string sip = drawer[i].getLocalIP();
            int port = drawer[i].getPort();
            Socket temp;
            temp.setTimeout(100);
            temp.connect(sip, port);
            temp.close();
        }
    }
}

unsigned int SocketArray::getType(unsigned int ind) {
    return lc_types.at(ind);
}
