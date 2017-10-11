// Socket class - implements BaseSocket for INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_SOCKET
#define __HPP_SOCKET

// INCLUDES

#include "BaseSocket.hpp"

#ifdef __SSLMITM
#include "openssl/ssl.h"
#include "String.hpp"
#endif

// DECLARATIONS

class Socket : public BaseSocket
{
    friend class FDTunnel;

    public:
    // create INET socket & clear address structs
    Socket();
    // create socket using pre-existing FD (address structs will be empty!)
    Socket(int fd);
    // create socket from pre-existing FD, storing given local & remote IPs
    Socket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip);

    // connect to given IP & port (following default constructor)
    int connect(const std::string &ip, int port);

    // bind to given port
    int bind(int port);
    // bind to given IP & port, for machines with multiple NICs
    int bind(const std::string &ip, int port);

    // accept incoming connections & return new Socket
    Socket *accept();

    // close socket & clear address structs
    void reset();

    // get remote IP/port
    std::string getPeerIP();
    int getPeerSourcePort();
    int getPort();
    void setPort(int port);
    unsigned long int getPeerSourceAddr();

    // get local IP
    std::string getLocalIP();
    int getLocalPort();

#ifdef __SSLMITM
    //use this socket as an ssl server
    int startSslClient(const std::string &certPath, String hostname);

    //is this a SSL connection
    bool isSsl();

    bool isSslServer();

    //shuts down the current ssl connection
    void stopSsl();

    //check that everything in this certificate is correct apart from the hostname
    long checkCertValid();

    //check the common name and altnames of a certificate against hostname
    int checkCertHostname(const std::string &hostame);

    void close();
#endif //__SSLMITM

#ifdef __SSLMITM
    //use this socket as an ssl server
    int startSslServer(X509 *x, EVP_PKEY *privKey, std::string &set_cipher);

    // non-blocking check for writable socket
    bool readyForOutput();
    bool breadyForOutput(int timeout);
    // blocking check, can break on config reloads
    void readyForOutput(int timeout, bool honour_reloadconfig = false) throw(std::exception);

    // non-blocking check for input data
    bool checkForInput();
    bool bcheckForInput(int timeout);

    // blocking check for data, can be told to break on signal triggered config reloads (-r)
    void checkForInput(int timeout, bool honour_reloadconfig = false) throw(std::exception);

    // get a line from the socket - can break on config reloads
    int getLine(char *buff, int size, int timeout, bool honour_reloadconfig = false, bool *chopped = NULL, bool *truncated = NULL) throw(std::exception);

    // write buffer to string - throws std::exception on error
    bool writeString(const char *line); //throw(std::exception);
    // write buffer to string - can be told not to do an initial readyForOutput, and told to break on -r
    bool writeToSocket(const char *buff, int len, unsigned int flags, int timeout, bool check_first = true, bool honour_reloadconfig = false);
    // read from socket, returning number of bytes read
    int readFromSocketn(char *buff, int len, unsigned int flags, int timeout);
    // read from socket, returning error status - can be told to skip initial checkForInput, and to break on -r
    int readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool check_first = true, bool honour_reloadconfig = false);
    // write to socket, throwing std::exception on error - can be told to break on -r
  //  void writeToSockete(const char *buff, int len, unsigned int flags, int timeout, bool honour_reloadconfig = false) throw(std::exception);
    void writeToSockete(const char *buff, int len, unsigned int flags, int timeout, bool honour_reloadconfig = false);
#endif //__SSLMITM

    private:
#ifdef __SSLMITM
    SSL *ssl;
    SSL_CTX *ctx;
    bool isssl;
    bool issslserver;
#else
    bool isssl;
#endif //__SSLMITM

    // local & remote addresses
    struct sockaddr_in my_adr;
    struct sockaddr_in peer_adr;
    int my_port;
};

#endif
