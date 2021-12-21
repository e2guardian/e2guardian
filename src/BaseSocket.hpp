// BaseSocket class - inherit & implement to make UNIX/INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_BASESOCKET
#define __HPP_BASESOCKET

// INCLUDES

#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <exception>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include "openssl/ssl.h"

#define SCK_READ_BUFF_SIZE 4096

class BaseSocket
{
    public:
    // create socket from FD - must be overridden to clear the relevant address structs in derived classes
    BaseSocket(int fd);

    // make a socket a listening server socket
    int listen(int queue);

    // grab socket's FD,
    // use sparingly, and DO NOT do manual data transfer with it
    int getFD();

    // close socket
    void close();

    // set socket-wide timeout
    void setTimeout(int t);
    int getTimeout();
    int getErrno();

    bool isClosing();
    bool isHup();
    bool sockError();
    bool isTimedout();
    bool isNoOpp();
    bool isNoRead();
    bool isNoWrite();
    bool isOpen();
    bool ishup;

    // close & reset the connection - these must clear address structures & call baseReset/baseAccept
    virtual void reset() = 0;
    virtual BaseSocket *accept() = 0;

    // non-blocking check for input data
    bool checkForInput(int timeout = 20);
    // non-blocking check for writable socket
    //bool readyForOutput();
    // blocking check
    bool readyForOutput(int timeout);

    // get a line from the socket
    int getLine(char *buff, int size, int timeout, bool *chopped = NULL, bool *truncated = NULL);

    // write string to socket
    bool writeString(const char *line);

    // write buff to socket - blocking
    bool writeToSocket(const char *buff, int len, unsigned int flags, int timeout);

    // write buff to socket - returns number of bytes written or 0 if would block or -1 on error
    int writeToSocketNB(const char *buff, int len, unsigned int flags);

    // read from socket, returning number of bytes read
    int readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool ret_part = false);
    short int get_wait_flag(bool write_flag);
    bool timedout = false;
    bool isNoBlock = false;
    bool doCheck = true;
    int buffstart = 0;
    int bufflen = 0;
    char buffer[SCK_READ_BUFF_SIZE];

    protected:
    // socket-wide timeout
    int timeout = 5000;
    int s_errno = 0;
    // length of address of other end of socket (e.g. size of sockaddr_in or sockaddr_un)
    socklen_t peer_adr_length;
    // socket FD
    int sck = -1;
    bool isclosing = false;
    //bool ishup;
    bool sockerr;
    //bool timedout;
    // internal buffer
    struct pollfd infds[1];
    struct pollfd outfds[1];

    // constructor - sets default values. override this if you actually wish to create a default socket.
    BaseSocket();
    // destructor - closes socket
    virtual ~BaseSocket();

    // performs accept(). call from derived classes' accept method
    int baseAccept(struct sockaddr *acc_adr, socklen_t *acc_adr_length);
    // closes socket & resets timeout to default - call from derived classes' reset method
    void baseReset();
};

#endif
