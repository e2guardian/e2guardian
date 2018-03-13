// Base socket class - inherit this to implement UNIX/INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include <csignal>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <syslog.h>
#include <sys/select.h>

#ifdef NETDEBUG
#include <iostream>
#endif

#include "BaseSocket.hpp"

// GLOBALS
extern bool reloadconfig;
extern thread_local std::string thread_id;

// DEFINITIONS

#define dgtimercmp(a, b, cmp) \
    (((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_usec cmp(b)->tv_usec) : ((a)->tv_sec cmp(b)->tv_sec))

#define dgtimersub(a, b, result)                     \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;    \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
    if ((result)->tv_usec < 0) {                     \
        (result)->tv_sec--;                          \
        (result)->tv_usec += 1000000;                \
    }

// IMPLEMENTATION

// This class contains client and server socket init and handling
// code as well as functions for testing and working with the socket FDs.

// constructor - override this if desired to create an actual socket at startup
BaseSocket::BaseSocket()
    : timeout(5000), sck(-1), buffstart(0), bufflen(0)
{
    infds[0].fd = -1;
    outfds[0].fd = -1;
    infds[0].events = POLLIN;
    outfds[0].events = POLLOUT;
    isclosing = false;
    timedout = false;
    sockerr = false;
    ishup = false;
    s_errno = 0;
}

// create socket from FD - must be overridden to clear the relevant address structs
BaseSocket::BaseSocket(int fd)
    : timeout(5000), buffstart(0), bufflen(0)
{
    sck = fd;
    infds[0].fd = fd;
    outfds[0].fd = fd;
    infds[0].events = POLLIN;
    outfds[0].events = POLLOUT;
    isclosing = false;
    timedout = false;
    sockerr = false;
    ishup = false;
    s_errno = 0;
}

// destructor - close socket
BaseSocket::~BaseSocket()
{
    // close fd if socket not used
    if (sck > -1) {
        ::close(sck);
    }
}

// reset - close socket & reset timeout.
// call this in derived classes' reset() method, which should also clear address structs
void BaseSocket::baseReset()
{
    if (sck > -1) {
        ::close(sck);
        sck = -1;
        infds[0].fd = -1;
        outfds[0].fd = -1;
    }
    timeout = 5000;
    buffstart = 0;
    bufflen = 0;
    isclosing = false;
    timedout = false;
    sockerr = false;
    ishup = false;
    s_errno = 0;
}

// mark a socket as a listening server socket
int BaseSocket::listen(int queue)
{
    return ::listen(sck, queue);
}

// "template adaptor" for accept - basically, let G++ do the hard work of
// figuring out the type of the third parameter ;)
template <typename T>
inline int local_accept_adaptor(int (*accept_func)(int, struct sockaddr *, T),
    int sck, struct sockaddr *acc_adr, socklen_t *acc_adr_length)
{
    return accept_func(sck, acc_adr, (T)acc_adr_length);
}

// receive an incoming connection & return FD
// call this in accept methods of derived classes, which should pass in empty sockaddr & socklen_t to be filled out
int BaseSocket::baseAccept(struct sockaddr *acc_adr, socklen_t *acc_adr_length)
{

    // OS X defines accept as:
    // int accept(int s, struct sockaddr *addr, int *addrlen);
    // but everyone else as:
    // int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
    // NB: except 10.4, which seems to use the more standard definition. grrr.
    return local_accept_adaptor(::accept, sck, acc_adr, acc_adr_length);
}

// return socket's FD - please use sparingly and DO NOT do manual data transfer using it
int BaseSocket::getFD()
{
    return sck;
}

// close the socket
void BaseSocket::close()
{
    if (sck > -1) {
        ::close(sck);
        sck = -1;
        infds[0].fd = -1;
        outfds[0].fd = -1;
    }
    buffstart = 0;
    bufflen = 0;
    isclosing = false;
    timedout = false;
    sockerr = false;
    ishup = false;
}

// set the socket-wide timeout
void BaseSocket::setTimeout(int t)
{
    timeout = t;
}

int BaseSocket::getErrno()
{
    return  s_errno;
}

// return timeout
int BaseSocket::getTimeout()
{
    return timeout;
}

bool BaseSocket::isOpen()
{
    return (sck > -1);
}

bool BaseSocket::isClosing()
{
    return isclosing;
}

bool BaseSocket::sockError()
{
    return sockerr;
}

bool BaseSocket::isTimedout()
{
    return timedout;
}

bool BaseSocket::isHup()
{
    return ishup;
}

bool BaseSocket::isNoOpp()
{
    return (timedout || sockerr || (ishup && !isclosing) || (sck < 0));
}

bool BaseSocket::isNoRead()
{
    return ( sockerr ||  (sck < 0));
}

bool BaseSocket::isNoWrite()
{
    return ( sockerr || ishup || (sck < 0));
}

// blocking check to see if there is data waiting on socket
bool BaseSocket::bcheckSForInput(int timeout)
{
    if (isNoRead())
        return false;
    int rc;
    s_errno = 0;
    errno = 0;
    rc = poll(infds, 1, timeout);
    if (rc == 0)
    {
        timedout = true;
        return false;   //timeout
    }
    timedout = false;
    if (rc < 0)
    {
        s_errno = errno;
        sockerr = true;
        return false;
    }
    if (infds[0].revents & POLLHUP) {
        ishup = true;
    }
    if ((infds[0].revents & (POLLHUP | POLLIN))) {
        return true;
    }
    sockerr = true;
    return false;   // must be POLLERR or POLLNVAL
}

// blocking check to see if there is data waiting on socket
bool BaseSocket::bcheckForInput(int timeout)
{
    if ((bufflen - buffstart) > 0)
        return true;
    if (isNoRead())
        return false;
    int rc;
    s_errno = 0;
    errno = 0;
    rc = poll(infds, 1, timeout);
    if (rc == 0)
    {
        timedout = true;
        return false;   //timeout
    }
    timedout = false;
    if (rc < 0)
    {
        s_errno = errno;
        sockerr = true;
        return false;
    }
    if (infds[0].revents & POLLHUP) {
        ishup = true;
    }
    if ((infds[0].revents & (POLLHUP | POLLIN))) {
        return true;
    }
    sockerr = true;
    return false;   // must be POLLERR or POLLNVAL
}

// blocking check for waiting data - blocks for up to given timeout, can be told to break on signal-triggered config reloads
bool BaseSocket::checkForInput()
{
    if ((bufflen - buffstart) > 0)
        return true;
    if (isNoRead())
        return false;
    int rc;
    s_errno = 0;
    errno = 0;
   rc = poll(infds, 1, 0);
    if (rc == 0)
        {
        return false;   //timeout
    }
    timedout = false;
    if (rc < 0)
    {
        s_errno = errno;
        sockerr = true;
        return false;
    }
    if (infds[0].revents & POLLHUP) {
        ishup = true;
    }
    if (infds[0].revents & (POLLHUP | POLLIN)) {
        return true;
    }
    sockerr = true;
    return false;   // must be POLLERR or POLLNVAL
}



// non-blocking check to see if a socket is ready to be written     //NOT EVER USED   - not it is used in Socket.cpp
bool BaseSocket::readyForOutput()
{
    if (isNoWrite())
        return false;
    int rc;
    s_errno = 0;
    errno = 0;
    rc = poll(outfds,1, 0);
    if (rc == 0)
    {
        return false;
    }
    timedout = false;
    if (rc < 0)
    {
        s_errno = errno;
        sockerr = true;
        return false;
    }
    if (outfds[0].revents & POLLOUT)
         return true;
    if (outfds[0].revents & POLLHUP)
        ishup = true;
    return false;
}

bool BaseSocket::breadyForOutput(int timeout) {
    if (isNoWrite())
        return false;
    int rc;
    s_errno = 0;
    errno = 0;
    rc = poll(outfds, 1, timeout);
    if (rc == 0) {
        timedout = true;
        return false;
    }
    timedout = false;
    if (rc < 0) {
        s_errno = errno;
        sockerr = true;
        return false;
    }
    if (outfds[0].revents & POLLOUT)
        return true;
    if (outfds[0].revents & POLLHUP)
        ishup = true;
    return false;
}

// read a line from the socket, can be told to break on config reloads
int BaseSocket::getLine(char *buff, int size, int timeout, bool honour_reloadconfig, bool *chopped, bool *truncated) //throw(std::exception)
{
    try {
        // first, return what's left from the previous buffer read, if anything
        int i = 0;
        if ((bufflen - buffstart) > 0) {
#ifdef NETDEBUG
            std::cout << thread_id  << "data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif

            //work out the maximum size we want to read from our internal buffer
            int tocopy = size - 1;
            if ((bufflen - buffstart) < tocopy)
                tocopy = bufflen - buffstart;

            //copy the data to output buffer (up to 8192 chars in loglines case)
            char *result = (char *) memccpy(buff, buffer + buffstart, '\n', tocopy);

            //if the result was < max size
            //if the result WAS null this indicates a full buffer copy
            if (result != NULL) {
                // indicate that a newline was chopped off, if desired
                if (chopped)
                    *chopped = true;

                //make the last char a null
                *(--result) = '\0';
                buffstart += (result - buff) + 1;
                return result - buff;
            } else {
                i += tocopy;
                buffstart += tocopy;
            }
        }
        while (i < (size - 1)) {
            buffstart = 0;
            bufflen = 0;
//        try {
            s_errno = 0;
            errno = 0;
            if (bcheckForInput(timeout))
                bufflen = recv(sck, buffer, 1024, 0);
            //      } catch (std::exception &e) {
            //          throw std::runtime_error(std::string("Can't read from socket: ") + e.what()); // on error
            //     }
#ifdef NETDEBUG
            std::cout << thread_id  << "getLine !SSL read into buffer; bufflen: " << bufflen << std::endl;
#endif
            //if there was a socket error
            if (bufflen < 0) {
#ifdef NETDEBUG
                std::cout << thread_id  << "getLine Can't read from socket !SSL: " << std::endl;
#endif
                s_errno = errno;
                return -1;
//            throw std::runtime_error(std::string("Can't read from socket: ") + strerror(errno)); // on error
            }
            //if socket closed...
            if (bufflen == 0) {
                buff[i] = '\0'; // ...terminate string & return what read
#ifdef NETDEBUG
                std::cout << thread_id  << "getLine terminate string !SSL: " << i << std::endl;
#endif
                if (truncated)
                    *truncated = true;
                return i;
            }
            int tocopy = bufflen;
            if ((i + bufflen) > (size - 1))
                tocopy = (size - 1) - i;
            char *result = (char *) memccpy(buff + i, buffer, '\n', tocopy);
            if (result != NULL) {
#ifdef NETDEBUG
                std::cout << thread_id  << "getLine result1 !SSL: " << result << i << std::endl;
#endif
                // indicate that a newline was chopped off, if desired
                if (chopped)
                    *chopped = true;
                *(--result) = '\0';
                buffstart += (result - (buff + i)) + 1;
#ifdef NETDEBUG
                std::cout << thread_id  << "getLine result2 !SSL: " << result << std::endl;
#endif
                return i + (result - (buff + i));
            }
            i += tocopy;
        }
        // oh dear - buffer end reached before we found a newline
        buff[i] = '\0';
        if (truncated)
            *truncated = true;
#ifdef NETDEBUG
        if (truncated)
            std::cout << thread_id  << "Getline(SSL) truncated buffer end reached before we found a newline: " << buff  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
        return i;
    } catch (...) {
        return -1;
    }
}

// write line to socket
bool BaseSocket::writeString(const char *line) //throw(std::exception)
{
    int l = strlen(line);
    return writeToSocket(line, l, 0, timeout);
}

// write data to socket - throws exception on failure, can be told to break on config reloads
//void BaseSocket::writeToSockete(const char *buff, int len, unsigned int flags, int timeout, bool honour_reloadconfig) throw(std::exception)
void BaseSocket::writeToSockete(const char *buff, int len, unsigned int flags, int timeout, bool honour_reloadconfig)
{
    if (!writeToSocket(buff, len, flags, timeout, honour_reloadconfig)) {
        throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));
    }
}

// write data to socket - can be told not to do an initial readyForOutput, and to break on config reloads
bool BaseSocket::writeToSocket(const char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
    int actuallysent = 0;
    int sent;
    while (actuallysent < len) {
        if (check_first) {
//            try {
                //readyForOutput(timeout, honour_reloadconfig); // throws exception on error or timeoutI/
            //} catch (std::exception &e) {
            //    return false;
            //}
            if(!breadyForOutput(timeout))
                return false;
        }
        sent = 0;
        s_errno = 0;
        errno = 0;
        if(!isNoWrite()) sent = send(sck, buff + actuallysent, len - actuallysent, 0);

//        if (sent == 0)
        if (sent  < 1)
        {
            s_errno = errno;
            return false; // other end is closed
        }
        actuallysent += sent;
    }
    return true;
}

// read a specified expected amount and return what actually read
int BaseSocket::readFromSocketn(char *buff, int len, unsigned int flags, int timeout)
{
    int cnt, rc;
    cnt = len;

    // first, return what's left from the previous buffer read, if anything
    if ((bufflen - buffstart) > 0) {
#ifdef NETDEBUG
        std::cout << thread_id  << "readFromSocketn: data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif
        int tocopy = len;
        if ((bufflen - buffstart) < len)
            tocopy = bufflen - buffstart;
        memcpy(buff, buffer + buffstart, tocopy);
        cnt -= tocopy;
        buffstart += tocopy;
        buff += tocopy;
        if (cnt == 0)
            return len;
    }

    while (cnt > 0) {
//        try {
//            checkForInput(timeout); // throws exception on error or timeout
//        } catch (std::exception &e) {
//            return -1;
//        }
//        if (isNoRead())  return -1;
        if (!bcheckForInput(timeout))  return -1;
        s_errno = 0;
        errno = 0;
        rc = recv(sck, buff, cnt, flags);
        if (rc < 0) {
//i            if (errno == EINTR) {
//                continue;
//            }
            s_errno = errno;
            return -1;
        }
        if (rc == 0) { // eof
            return len - cnt;
        }
        buff += rc;
        cnt -= rc;
    }
    return len;
}

// read what's available and return error status - can be told not to do an initial checkForInput, and to break on reloads
int BaseSocket::readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
    // first, return what's left from the previous buffer read, if anything
    int cnt = len;
    int tocopy = 0;
    if ((bufflen - buffstart) > 0) {
        tocopy = len;

#ifdef NETDEBUG
        std::cout << thread_id  << "readFromSocket: data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif
        if ((bufflen - buffstart) < len)
            tocopy = bufflen - buffstart;

        memcpy(buff, buffer + buffstart, tocopy);
        cnt -= tocopy;
        buffstart += tocopy;
        buff += tocopy;

        if (cnt == 0)
            return len;
    }

    int rc = 0;

    if (check_first) {
    //    try {
    //        checkForInput(timeout, honour_reloadconfig);
    //    } catch (std::exception &e) {
    //        return -1;
    //    }
        if (! bcheckForInput(timeout))
            return -1;
    }
    while (true) {
        if (isNoRead())  return -1;
        s_errno = 0;
        errno = 0;
        rc = recv(sck, buff, cnt, flags);
        if (rc < 0) {
 //           if (errno == EINTR ) {
//  ..             continue;
//           }
            s_errno = errno;
            return -1;
       }

        break;
    }
    return rc + tocopy;
}
