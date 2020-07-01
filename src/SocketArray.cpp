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
    logger_debug("bindSingle binding port", port);
    lc_types.push_back(CT_PROXY);
    return drawer[0].bind(port);
}

int SocketArray::bindSingle(unsigned int index, int port, unsigned int type)
{
    if (socknum <= index) {
        return -1;
    }
    logger_debug("bindSingle binding port", port, " with type ", type);
    lc_types.push_back(type);
    return drawer[index].bind(port);
}


// bind our first socket to any IP and one or more ports
int SocketArray::bindSingleM(std::deque<String> &ports)
{
    if (socknum < ports.size()) {
        return -1;
    }
    for (unsigned int i = 0; i < ports.size(); i++) {
        logger_debug("bindSingleM binding port", ports[i]);
        if (drawer[i].bind(ports[i].toInteger())) {
            logger_error("Error binding server socket: [", ports[i], " ", i, "] (", strerror(errno), ")");
            return -1;
        }
        lc_types.push_back(CT_PROXY);
    }
    return 0;
}

// return an array of our socket FDs
int *SocketArray::getFDAll()
{
    int *fds = new int[socknum];
    for (unsigned int i = 0; i < socknum; i++) {
        logger_debug("Socket ", i, " fd:", drawer[i].getFD() );
        fds[i] = drawer[i].getFD();
    }
    return fds;
}

// listen on all IPs with given kernel queue size
int SocketArray::listenAll(int queue)
{
    for (unsigned int i = 0; i < socknum; i++) {
        if (drawer[i].listen(queue)) {
            logger_error("Error listening to socket");
            return -1;
        }
    }
    return 0;
}

// bind all sockets to given IP list
int SocketArray::bindAll(std::deque<String> &ips, std::deque<String> &ports)
{
    if (ips.size() > socknum) {
        return -1;
    }
    //for (unsigned int i = 0; i < socknum; i++) {
    for (unsigned int i = 0; i < ips.size(); i++) {
        logger_debug("Binding server socket[", ports[i], " ", ips[i], " ", i, "]" );
        if (drawer[i].bind(ips[i].toCharArray(), ports[i].toInteger())) {
            logger_error("Error binding server socket: [", ports[i], " ", ips[i], " ", i, "] (", strerror(errno), ")" );
            return -1;
        }
        lc_types.push_back(CT_PROXY);
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
