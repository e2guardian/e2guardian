// UdpSocket class - implements BaseSocket for INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_UDPSOCKET
#define __HPP_UDPSOCKET

// INCLUDES

#include "BaseSocket.hpp"
#include "String.hpp"
#include <sstream>
#include <iomanip>

//#include "openssl/ssl.h"
#include "String.hpp"

// DECLARATIONS

class UdpSocket : public BaseSocket
{
    //friend class FDTunnel;

    public:
    // create INET socket & clear address structs
    UdpSocket();
    // create socket using pre-existing FD (address structs will be empty!)
    UdpSocket(int fd);
    // create socket from pre-existing FD, storing given local & remote IPs
    UdpSocket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip);
    ~UdpSocket();

    // connect to given IP & port (following default constructor)
    int connect(const std::string &ip, int port);

    // bind to given port
    int bind(int port);
    // bind to given IP & port, for machines with multiple NICs
    int bind(const std::string &ip, int port);

    // accept incoming connections & return new UdpSocket
    UdpSocket *accept();

    // close socket & clear address structs
    void reset();

    // get remote IP/port
    std::string getPeerIP();
    int getPeerSourcePort();
    int getPort();
    void setPort(int port);
    void setClientAddr( std::string ip, int port);
    unsigned long int getPeerSourceAddr();

    //std::string down_thread_id;

    // get local IP
    std::string getLocalIP();
    int getLocalPort();

    short int get_wait_flag(bool write_flag);

    void close();


    // blocking check, can break on config reloads
    //void readyForOutput(int timeout, bool honour_reloadconfig = false);


    // write buffer to string
    bool writeString(const char *line);
    bool writeString(std::string line);

    // write buff to socket - blocking
    bool writeToSocket(const char *buff, int len, unsigned int flags, int timeout);

    // write buff to socket non-blocking - returns number of bytes written or 0 if would block or -1 on error
    int writeToSocketNB(const char *buff, int len, unsigned int flags);

    // read from socket, returning number of bytes read
    int readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool ret_part = false);

    bool getIeof();

    private:

    // local & remote addresses
    struct sockaddr_in my_adr;
    struct sockaddr_in peer_adr;
    int my_port = 0;
    std::string my_addr;
    int client_port = 0;
    std::string client_addr;
    bool ieof = false;
};

#endif
