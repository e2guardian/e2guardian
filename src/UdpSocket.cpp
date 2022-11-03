// UdpSocket class - implements BaseSocket for INET domain sockets

// Note:  This class is only tested for UDP send at present other functions (such as listen, read etc may not currently work!!! PIP

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "UdpSocket.hpp"
#include "Logger.hpp"

#include <string.h>
#include <csignal>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <stdexcept>
#include <cerrno>
#include <unistd.h>
#include <netinet/tcp.h>
#include "String.hpp"

extern bool reloadconfig;


// IMPLEMENTATION
//
// destructor
UdpSocket::~UdpSocket() {
    close();
}

// constructor - create an INET socket & clear address structures
UdpSocket::UdpSocket() {
    sck = socket(AF_INET, SOCK_DGRAM, 0);
    if (sck < 0) {
        s_errno = errno;
    } else {
        memset(&my_adr, 0, sizeof my_adr);
        memset(&peer_adr, 0, sizeof peer_adr);
        my_adr.sin_family = AF_INET;
        peer_adr.sin_family = AF_INET;
        peer_adr_length = sizeof(struct sockaddr_in);
        int f = 1;

        if (sck > 0)
            setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));

        my_port = 0;
    }
}

// create socket from pre-existing FD (address structs will be invalid!)
UdpSocket::UdpSocket(int fd)
        : BaseSocket(fd) {
    memset(&my_adr, 0, sizeof my_adr);
    memset(&peer_adr, 0, sizeof peer_adr);
    my_adr.sin_family = AF_INET;
    peer_adr.sin_family = AF_INET;
    peer_adr_length = sizeof(struct sockaddr_in);
    int f = 1;

    int res = setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));
    if (res < 0) s_errno = errno;
    my_port = 0;
}

// create socket from pre-existing FD, storing local & remote IPs
UdpSocket::UdpSocket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip)
        : BaseSocket(newfd) {
    memset(&my_adr, 0, sizeof my_adr); // ***
    memset(&peer_adr, 0, sizeof peer_adr); // ***
    my_adr.sin_family = AF_INET; // *** Fix suggested by
    peer_adr.sin_family = AF_INET; // *** Christopher Weimann
    my_adr = myip;
    peer_adr = peerip;
    peer_adr_length = sizeof(struct sockaddr_in);
    int f = 1;

    int res = setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));
    if (res < 0) s_errno = errno;
    my_port = 0;
}

// find the ip to which the client has connected
std::string UdpSocket::getLocalIP() {
    char res[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET,&my_adr.sin_addr, res, sizeof(res));
}

// find the ip of the client connecting to us
std::string UdpSocket::getPeerIP() {
    if (!client_addr.empty()) {
        return client_addr;
    } else {
        char res[INET_ADDRSTRLEN];
        return inet_ntop(AF_INET, &peer_adr.sin_addr, res, sizeof(res));
    }
}

// find the port of the client connecting to us
int UdpSocket::getPeerSourcePort() {
    return ntohs(peer_adr.sin_port);
}

int UdpSocket::getPort() {
    return my_port;
}

void UdpSocket::setPort(int port) {
    my_port = port;
}

// return the address of the client connecting to us
unsigned long int UdpSocket::getPeerSourceAddr() {
    return (unsigned long int) ntohl(peer_adr.sin_addr.s_addr);
}

// close connection & wipe address structs
void UdpSocket::reset() {
    this->baseReset();

    sck = socket(AF_INET, SOCK_DGRAM, 0);
    if (sck < 0) {
        s_errno = errno;
        return;
    }

    memset(&my_adr, 0, sizeof my_adr);
    memset(&peer_adr, 0, sizeof peer_adr);
    my_adr.sin_family = AF_INET;
    peer_adr.sin_family = AF_INET;
    peer_adr_length = sizeof(struct sockaddr_in);
    infds[0].fd = sck;
    outfds[0].fd = sck;

}

// connect to given IP & port (following default constructor)
int UdpSocket::connect(const std::string &ip, int port) {
    reset();   // do it anyway as we need sck to be allocated

    if (sck < 0) // socket creation error
    {
        return -1;
    }
    bind(39000); // otherwise source port allocated on each send confusing destination server. f/w etc

    int len = sizeof my_adr;
    peer_adr.sin_port = htons(port);
    inet_aton(ip.c_str(), &peer_adr.sin_addr);
    my_port = port;
    peer_adr_length = sizeof peer_adr;
    int save_flags = fcntl(sck,F_GETFL);
    fcntl(sck, F_SETFL, save_flags | O_NONBLOCK);
    s_errno = 0;
    errno = 0;
    int ret = ::connect(sck, (struct sockaddr *) &peer_adr, len);
    if (ret < 0 && errno == EINPROGRESS) ret = 0;
    else s_errno = errno;
    if (ret == 0) {
        int rc = poll(outfds, 1, timeout);
        if (rc == 0) {
            timedout = true;
            ret = -1;
        } else if (rc < 0) {
            s_errno = errno;
            ret = -1;
        } else {
            int so_error;
            socklen_t len = sizeof so_error;
            getsockopt(sck, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error != 0) {
                sockerr = true;
                s_errno = so_error;
                ret = -1;
            } else {
                ret = 0;
            }
        }
    }
    if (ret < 0) {
        close();
    } else {
        save_flags = fcntl(sck,F_GETFL);
        fcntl(sck, F_SETFL, save_flags & ~O_NONBLOCK);
    }
    return ret;
}

// bind socket to given port
int UdpSocket::bind(int port) {
    int len = sizeof my_adr;
    int i = 1;

    setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_port = port;

    return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// bind socket to given port & IP
int UdpSocket::bind(const std::string &ip, int port) {
    int len = sizeof my_adr;
    int i = 1;

    setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_adr.sin_addr.s_addr = inet_addr(ip.c_str());
    my_port = port;

    return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// accept incoming connections & return new UdpSocket
UdpSocket *UdpSocket::accept() {
    peer_adr_length = sizeof(struct sockaddr_in);
    s_errno = 0;
    errno = 0;
    int newfd = ::accept(sck, (struct sockaddr *) &peer_adr, &peer_adr_length);

    if (newfd > 0) {
        UdpSocket *s = new UdpSocket(newfd, my_adr, peer_adr);
        s->setPort(my_port);
        return s;
    } else {
        s_errno = errno;
        return NULL;
   }
}



void UdpSocket::close()
{

    BaseSocket::close();
}



// write line to socket
bool UdpSocket::writeString(std::string line)
{
    int l = line.length();
    return writeToSocket(line.c_str(), l, 0, timeout);
}

// write data to socket
bool UdpSocket::writeToSocket(const char *buff, int len, unsigned int flags, int timeout)
{
    if (len == 0)   // nothing to write
        return true;
    if (true) {
        return BaseSocket::writeToSocket(buff, len, flags, timeout);
    }


    return true;
}

int UdpSocket::readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool ret_part )
{
    if (len == 0)  // nothing to read
         return 0;
    if (true) {
        return BaseSocket::readFromSocket(buff, len, flags, timeout, ret_part);
    }

    // first, return what's left from the previous buffer read, if anything
    int cnt = len;
    int tocopy = 0;
    if ((bufflen - buffstart) > 0) {
        DEBUG_network("Socket::readFromSocket: data already in buffer; bufflen: ", bufflen, " buffstart: ", buffstart );
        tocopy = len;
        if ((bufflen - buffstart) < len)
            tocopy = bufflen - buffstart;
        memcpy(buff, buffer + buffstart, tocopy);
        cnt -= tocopy;
        buffstart += tocopy;
        buff += tocopy;
        if(ret_part) return tocopy;
        if (cnt == 0)
            return len;
    }

      return len;
}


bool UdpSocket::getIeof() {
    return ieof;
}



void UdpSocket::setClientAddr(std::string ip, int port) {
    client_addr = ip;
    client_port = port;
}
