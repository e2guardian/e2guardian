// Base socket class - inherit this to implement UNIX/INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include <csignal>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <sys/select.h>

#include "BaseSocket.hpp"
#include "Logger.hpp"

// GLOBALS
extern bool reloadconfig;

// DEFINITIONS

// IMPLEMENTATION

// This class contains client and server socket init and handling
// code as well as functions for testing and working with the socket FDs.

// constructor - override this if desired to create an actual socket at startup
BaseSocket::BaseSocket()
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
   // timeout = 5000;   // commented out so that timeout can be set before a connect call
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
bool BaseSocket::checkForInput(int timeout)
{
    if ((bufflen - buffstart) > 0)
        return true; // is data left in buffer

    if (isNoRead())
        return false;

    if(timeout == 0) { // no poll wanted as done by calling function
         return false;
    }

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


bool BaseSocket::readyForOutput(int timeout) {
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

// read a line from the socket
int BaseSocket::getLine(char *buff, int size, int timeout, bool *chopped, bool *truncated)
{
    try {
        // first, return what's left from the previous buffer read, if anything
        int i = 0;
        if ((bufflen - buffstart) > 0) {
            DEBUG_network("data already in buffer; bufflen: ", bufflen, " buffstart: ", buffstart);

            //work out the maximum size we want to read from our internal buffer
            int tocopy = size - 1;
            if ((bufflen - buffstart) < tocopy)
                tocopy = bufflen - buffstart;

            //copy the data to output buffer
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
            s_errno = 0;
            errno = 0;
            if (!isNoBlock) {
                if(!checkForInput(timeout))
                    return -1;
            }
            bufflen = recv(sck, buffer, SCK_READ_BUFF_SIZE, 0);
            if (bufflen < 0) {
                if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                    if(isNoBlock) {
                        if (checkForInput(timeout)) continue;// now got some input
                        else  return -1;// timed out
                    }
                }
                s_errno = errno;
                return -1;
            }
            //if socket closed...
            if (bufflen == 0) {
                buff[i] = '\0'; // ...terminate string & return what read
                DEBUG_network("getLine terminate string !SSL: ", i );
                if (truncated)
                    *truncated = true;
                return i;
            }
            int tocopy = bufflen;
            if ((i + bufflen) > (size - 1))
                tocopy = (size - 1) - i;
            char *result = (char *) memccpy(buff + i, buffer, '\n', tocopy);
            if (result != NULL) {
                DEBUG_network("getLine result1 !SSL: ", result, i );
                // indicate that a newline was chopped off, if desired
                if (chopped)
                    *chopped = true;
                *(--result) = '\0';
                buffstart += (result - (buff + i)) + 1;
                DEBUG_network("getLine result2 !SSL: ", result );
                return i + (result - (buff + i));
            }
            i += tocopy;
        }
        // oh dear - buffer end reached before we found a newline
        buff[i] = '\0';
        if (truncated)
            *truncated = true;
        if (truncated)
            DEBUG_network("Getline(SSL) truncated buffer end reached before we found a newline: ", buff );

        return i;
    } catch (...) {
        return -1;
    }
}

// write line to socket
bool BaseSocket::writeString(const char *line)
{
    int l = strlen(line);
    return writeToSocket(line, l, 0, timeout);
}

bool BaseSocket::writeToSocket(const char *buff, int len, unsigned int flags, int timeout)
{
    int actuallysent = 0;
    int sent;
    while (actuallysent < len) {
        sent = 0;
        s_errno = 0;
        errno = 0;
        if(isNoWrite()) return false;
        if((!isNoBlock) && doCheck) {
            if( !readyForOutput(timeout)) {
                s_errno = errno;
                return false;
            }
        }
        sent = send(sck, buff + actuallysent, len - actuallysent, 0);

        if (sent  < 1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                if(isNoBlock)
                    if (readyForOutput(timeout)) continue; // now able to send
            }
            s_errno = errno;
            return false; // other end is closed
        }
        actuallysent += sent;
    }
    return true;

}

// write data to socket - returns no of bytes written or 0 if would block and -1 on error
int BaseSocket::writeToSocketNB(const char *buff, int len, unsigned int flags)
{
    int actuallysent = 0;
    int sent;
    while (actuallysent < len) {
        sent = 0;
        s_errno = 0;
        errno = 0;
        if(isNoWrite()) return -1;
        if((!isNoBlock) && doCheck) {
            if (!readyForOutput(0))
                return 0;
        }
        sent = send(sck, buff + actuallysent, len - actuallysent, 0);

            if (sent  < 1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                s_errno = errno;
                return 0;
            }
                s_errno = errno;
                return -1; // other end is closed
            }
        actuallysent += sent;
            return sent;
    }
    return -1;    //should never get here
}

// read a specified expected amount and return what actually read
int BaseSocket::readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool ret_part)
{
    int cnt, rc;
    cnt = len;

    // first, return what's left from the previous buffer read, if anything
    if ((bufflen - buffstart) > 0) {
        DEBUG_network("data already in buffer; bufflen: ", bufflen, " buffstart: ", buffstart);
        int tocopy = len;
        if ((bufflen - buffstart) < len)
            tocopy = bufflen - buffstart;
        memcpy(buff, buffer + buffstart, tocopy);
        cnt -= tocopy;
        buffstart += tocopy;
        buff += tocopy;
        if (ret_part)
            return tocopy;
        if (cnt == 0)
            return len;
    }

    while (cnt > 0) {
        s_errno = 0;
        errno = 0;
        if((!isNoBlock) && doCheck) {
            if(!checkForInput(timeout))
                return -1;
        }
        rc = recv(sck, buff, cnt, flags);
        if (rc < 0) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                if (checkForInput(timeout)) continue;// now got some input
                else  {
                    timedout = true;
                    return -1;// timed out
                }
            }
            s_errno = errno;
            return -1;
        }
        if (rc == 0) { // eof
            ishup = true;
            return len - cnt;
        }
        cnt -= rc;
        if(ret_part) return len - cnt;
        buff += rc;
    }
    return len;
}


short int BaseSocket::get_wait_flag(bool write_flag) {
    if (timedout)
        timedout = false;
    if (write_flag) {
        return POLLOUT;
    }
    return POLLIN;
}
