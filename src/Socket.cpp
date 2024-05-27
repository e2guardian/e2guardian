// Socket class - implements BaseSocket for INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "Socket.hpp"
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

#include "openssl/x509v3.h"
#include "openssl/asn1.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "String.hpp"
#include "CertificateAuthority.hpp"

extern bool reloadconfig;

#ifndef X509_V_FLAG_TRUSTED_FIRST
#warning "openssl X509_V_FLAG_TRUSTED_FIRST not available, certificate chain creation will be unreliable and will fail on some sites"
#warning "To fix install a later version of openssl"
#define X509_V_FLAG_TRUSTED_FIRST 0
#endif


// IMPLEMENTATION
//
// destructor
Socket::~Socket() {
    close();
}

// constructor - create an INET socket & clear address structures
Socket::Socket() {
    sck = socket(AF_INET, SOCK_STREAM, 0);
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
        chunkError = false;

        ssl = NULL;
        ctx = NULL;
        isssl = false;
        issslserver = false;
    }
}

// create socket from pre-existing FD (address structs will be invalid!)
Socket::Socket(int fd)
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
    chunkError = false;

    ssl = NULL;
    ctx = NULL;
    isssl = false;
    issslserver = false;
}

// create socket from pre-existing FD, storing local & remote IPs
Socket::Socket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip)
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
    chunkError = false;

    ssl = NULL;
    ctx = NULL;
    isssl = false;
    issslserver = false;
    //fcntl(sck, F_SETFL, O_NONBLOCK);
}

// find the ip to which the client has connected
std::string Socket::getLocalIP() {
    char res[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET,&my_adr.sin_addr, res, sizeof(res));
}

// find the ip of the client connecting to us
std::string Socket::getPeerIP() {
    if (!client_addr.empty()) {
        return client_addr;
    } else {
        char res[INET_ADDRSTRLEN];
        return inet_ntop(AF_INET, &peer_adr.sin_addr, res, sizeof(res));
    }
}

// find the port of the client connecting to us
int Socket::getPeerSourcePort() {
    return ntohs(peer_adr.sin_port);
}

int Socket::getPort() {
    return my_port;
}

void Socket::setPort(int port) {
    my_port = port;
}

// return the address of the client connecting to us
unsigned long int Socket::getPeerSourceAddr() {
    return (unsigned long int) ntohl(peer_adr.sin_addr.s_addr);
}

// close connection & wipe address structs
void Socket::reset() {
    if (isssl) {
        stopSsl();
    }
    this->baseReset();

    sck = socket(AF_INET, SOCK_STREAM, 0);
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

    chunkError = false;
    chunk_to_read = 0;

}

// connect to given IP & port (following default constructor)
int Socket::connect(const std::string &ip, int port) {
    reset();   // do it anyway as we need sck to be allocated

    if (sck < 0) // socket creation error
    {
        return -1;
    }

    int len = sizeof my_adr;
    peer_adr.sin_port = htons(port);
    inet_aton(ip.c_str(), &peer_adr.sin_addr);
    my_port = port;
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
int Socket::bind(int port) {
    int len = sizeof my_adr;
    int i = 1;

    setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_port = port;

    return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// bind socket to given port & IP
int Socket::bind(const std::string &ip, int port) {
    int len = sizeof my_adr;
    int i = 1;

    setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_adr.sin_addr.s_addr = inet_addr(ip.c_str());
    my_port = port;

    return ::bind(sck, (struct sockaddr *) &my_adr, len);
}

// accept incoming connections & return new Socket
Socket *Socket::accept() {
    peer_adr_length = sizeof(struct sockaddr_in);
    s_errno = 0;
    errno = 0;
    int newfd = ::accept(sck, (struct sockaddr *) &peer_adr, &peer_adr_length);

    if (newfd > 0) {
        Socket *s = new Socket(newfd, my_adr, peer_adr);
        s->setPort(my_port);
        return s;
    } else {
        s_errno = errno;
        return NULL;
   }
}

//use this socket as an ssl client
int Socket::startSslClient(const std::string &certificate_path, String hostname)
{
    if (isssl) {
        stopSsl();
    }

    ERR_clear_error();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#error "openssl version 1.1 or greater is required"
#else
    ctx = SSL_CTX_new(TLS_client_method());
#endif

    if (ctx == NULL) {
        log_ssl_errors("Error ssl context is null for ", hostname.c_str());
        return -1;
    }

    //set the timeout for the ssl session
    if (SSL_CTX_set_timeout(ctx, 130l) < 1) {
            SSL_CTX_free(ctx);
            ctx = NULL;
        return -1;
    }

    //load certs
    ERR_clear_error();
    if (certificate_path.length()) {
        if (!SSL_CTX_load_verify_locations(ctx, NULL, certificate_path.c_str())) {
            log_ssl_errors("couldnt load certificates from ", certificate_path.c_str());
            //tidy up
            SSL_CTX_free(ctx);
            ctx = NULL;
            return -2;
        }
    } else if (!SSL_CTX_set_default_verify_paths(ctx)) //use default if no certPpath given
    {
        log_ssl_errors("couldnt load default certificates for ", hostname.c_str());
        //tidy up
        SSL_CTX_free(ctx);
        ctx = NULL;
        return -2;
    }

    // add validation params
    ERR_clear_error();
    X509_VERIFY_PARAM *x509_param = X509_VERIFY_PARAM_new();
    if (!x509_param) {
        log_ssl_errors("couldnt add validation params for %s", hostname.c_str());
            SSL_CTX_free(ctx);
            ctx = NULL;
        return -2;
    }

 // X509_V_FLAG_TRUSTED_FIRST is set by default in ossl v1.1 and above - so no need for this check
    //ERR_clear_error();
    //if (!X509_VERIFY_PARAM_set_flags(x509_param, X509_V_FLAG_TRUSTED_FIRST)) {
        //log_ssl_errors("couldnt add validation params for %s", hostname.c_str());
        //X509_VERIFY_PARAM_free(x509_param);
        //SSL_CTX_free(ctx);
        //ctx = NULL;
        //return -2;
    //}

   // ERR_clear_error();
   // X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
   // X509_VERIFY_PARAM_set_hostflags(param,X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS );

    // moved from checkCertValid

    // kulge to check theory in use of illegal char in dns name
    //{
        //String t = hostname;
        //if (t.contains("_")) {
            //t.swapChar('_','-');
            //hostname = t;
        //}
    //}

    DEBUG_debug("Adding hostname to check:",hostname,":");

    // moved from checkCertValid
    ERR_clear_error();
    if (!X509_VERIFY_PARAM_set1_host(x509_param, hostname.c_str(), hostname.length())) {
        log_ssl_errors("couldnt add validation params for %s", hostname.c_str());
        X509_VERIFY_PARAM_free(x509_param);
            SSL_CTX_free(ctx);
            ctx = NULL;
        return -2;
    }

    ERR_clear_error();
    if (!SSL_CTX_set1_param(ctx, x509_param)) {
        log_ssl_errors("couldnt add validation params for %s", hostname.c_str());
        X509_VERIFY_PARAM_free(x509_param);
            SSL_CTX_free(ctx);
            ctx = NULL;
        return -2;
    }

    //X509_VERIFY_PARAM_free(x509_param);     // try not freeing this as SSL_CTX_free seems to be ring to free it

    //hand socket over to ssl lib
    ERR_clear_error();
    ssl = SSL_new(ctx);
    SSL_set_options(ssl, SSL_OP_ALL);
    SSL_set_connect_state(ssl);

    SSL_set_fd(ssl, this->getFD());
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
    X509_VERIFY_PARAM_set1_host(SSL_get0_param(ssl), hostname.c_str(),0);

    int rc = 0;
    while (rc != 1) {
        ERR_clear_error();
        rc = SSL_connect(ssl);
        DEBUG_network("ssl_connect returned ", rc );

        if (rc != 1) {
            s_errno = SSL_get_error(ssl,rc);
            DEBUG_network("ssl_connect s_error is ", s_errno);
            switch (s_errno) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    if (ssl_poll_wait(s_errno, timeout)) continue;
                    timedout = true;
                default:
                    log_ssl_errors("ssl_connect failed to %s", hostname.c_str());
                    DEBUG_network("ssl_connect failed with error ", SSL_get_error(ssl, rc));
                    // tidy up
                    SSL_free(ssl);
                    ssl = NULL;
                    SSL_CTX_free(ctx);
                    ctx = NULL;
                    return -3;
            }
        }
        }

    isssl = true;
    issslserver = false;
    return 0;
}

bool Socket::isSsl()
{
    return isssl;
}

bool Socket::isSslServer()
{
    return issslserver;
}

//shuts down the current ssl connection
void Socket::stopSsl()
{
    DEBUG_network("ssl stopping");
    if(!isssl) return;

    isssl = false;

    if (ssl != NULL) {
        if (issslserver) {
#ifdef DEBUG_LOW
            DEBUG_network("this is a server connection");
            if (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) {
                DEBUG_network("SSL_SENT_SHUTDOWN IS SET");
            }
            if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
                DEBUG_network("SSL_RECEIVED_SHUTDOWN IS SET");
            }
#endif
            DEBUG_network("calling 1st ssl shutdown");

            int rc = 0;
            while (rc != 1) {
                ERR_clear_error();
                rc = SSL_shutdown(ssl);
                DEBUG_network("SSL_shutdown returns ", rc);
                //if (rc == 0) continue;
                if (rc == 0) break;
                if (rc != 1) {
                    s_errno = SSL_get_error(ssl,rc);
                    DEBUG_network("s_errno ", s_errno);
                    switch (s_errno) {
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                            if (ssl_poll_wait(s_errno, timeout)) continue;
                            DEBUG_network("timed out ", timeout);
                            break;
                        default:
                            DEBUG_network("Error shutitng down SSL ", s_errno );
                            log_ssl_errors("ssl_shutdown failed ","");
                            break;
                    }
                }
                break;
            }
            if (rc == 0) {
                DEBUG_network("Discarding extra data from client");

                shutdown(SSL_get_fd(ssl), SHUT_WR);
                char junk[1024];
                readFromSocket(junk, sizeof(junk), 0, 5);
                DEBUG_network("done");
            }
        } else {
#ifdef DEBUG_LOW
            DEBUG_network("this is a client connection");
            if (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) {
                DEBUG_network("SSL_SENT_SHUTDOWN IS SET");
            }
            if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
                DEBUG_network("SSL_RECEIVED_SHUTDOWN IS SET");
            }
            DEBUG_network("calling ssl shutdown");
#endif
            int rc = 0;
            while (rc != 1) {
                ERR_clear_error();
                rc = SSL_shutdown(ssl);
                DEBUG_network("SSL_shutdown returns ", rc);
             //   if (rc == 0) continue;
                if (rc == 0) break;
                if (rc != 1) {
                    s_errno = SSL_get_error(ssl,rc);
                    DEBUG_network("s_errno ", s_errno);
                    switch (s_errno) {
                        case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                            if (ssl_poll_wait(s_errno, timeout)) continue;
                            break;
                        default:
                            DEBUG_network("Error shutitng down SSL", s_errno );
                            log_ssl_errors("ssl_shutdwon failed ","");
                            break;
                    }
                }
                break;
            }
            DEBUG_network("done");
        }
    }

    cleanSsl();

}

void Socket::cleanSsl() {  // called when failure in ssl set up functions and from stopSsl
    if (ssl != NULL) {
        SSL_free(ssl);
        ssl = NULL;
    }
    if (ctx != NULL ) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
    issslserver = false;
    isssl = false;
}

//check that everything in this certificate is correct appart from the hostname
long Socket::checkCertValid(String &hostname)
{
    //check we have a certificate
    X509 *peerCert = SSL_get_peer_certificate(ssl);
    if (peerCert == NULL) {
        return -1;
    }
    X509_free(peerCert);

// Moved to startSslClient
//    X509_VERIFY_PARAM *param;
    //param = X509_VERIFY_PARAM_new() ;
    //X509_VERIFY_PARAM_set1_host(param,hostname.c_str(), hostname.length());
    //SSL_CTX_set1_param(ctx,param);
    //X509_VERIFY_PARAM_free(param);
    return SSL_get_verify_result(ssl);
}

//check the common name and altnames of a certificate against hostname
int Socket::checkCertHostname(const std::string &_hostname)
{
    return 0;    //TODO
}

void Socket::close()
{
    if (isssl) {
        stopSsl();
    }
    BaseSocket::close();
}

//use this socket as an ssl server
int Socket::startSslServer(X509 *x, EVP_PKEY *privKey, std::string &set_cipher_list)
{

    if (isssl) {
        stopSsl();
    }

    // set ssl to NULL
    ssl = NULL;

    //setup the ssl server ctx
    ctx = SSL_CTX_new(TLS_server_method());

    if (ctx == NULL) {
        DEBUG_network("Error ssl context is null (check that openssl has been inited)");
        return -1;
    }

    //set the timeout to match firefox
    if (SSL_CTX_set_timeout(ctx, 130l) < 1) {
        cleanSsl();
        return -1;
    }

    //set the ctx to use the certificate
    if (SSL_CTX_use_certificate(ctx, x) < 1) {
        DEBUG_network("Error using certificate");
        cleanSsl();
        return -1;
    }

    if (set_cipher_list.length() > 0)
        SSL_CTX_set_cipher_list(ctx, set_cipher_list.c_str());

    //set the ctx to use the private key
    if (SSL_CTX_use_PrivateKey(ctx, privKey) < 1) {
        DEBUG_network("Error using private key");
        cleanSsl();
        return -1;
    }

    //setup the ssl session
    ERR_clear_error();
    ssl = SSL_new(ctx);
    SSL_set_options(ssl, SSL_OP_ALL);
   // SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_accept_state(ssl);

    ERR_clear_error();
    if(!SSL_set_fd(ssl, this->getFD())) {
        log_ssl_errors("ssl_set_fd failed to client", "");
        cleanSsl();
        return -1;
    };

    int rc = 0;
    while (rc != 1) {
        ERR_clear_error();
        rc = SSL_accept(ssl);
        DEBUG_network("accepting returns ", rc);
        if (rc != 1) {
                s_errno = SSL_get_error(ssl,rc);
                switch (s_errno) {
                    case SSL_ERROR_WANT_READ:
                        case SSL_ERROR_WANT_WRITE:
                        if (ssl_poll_wait(s_errno, timeout)) continue;
                        timedout = true;
                        return -1;
                    default:
                        DEBUG_network("Error accepting ssl connection error is ", s_errno );
                        log_ssl_errors("ssl_accept failed to client %s", "");
                        cleanSsl();
                        return -1;
                }
        }
    }

    ERR_clear_error();
    if (SSL_do_handshake(ssl) < 0) {
        log_ssl_errors("ssl_handshake failed to client ", "");
        cleanSsl();
        return -1;
    }
    SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
    isssl = true;
    issslserver = true;
    return 0;
}

bool Socket::checkForInput(int timeout)
{
    if (!isssl) {
        return BaseSocket::checkForInput(timeout);
    }

    //if(timeout == 0)
    //    return false;

    DEBUG_network("checking for input on ssl connection");
    if ((bufflen - buffstart) > 0) {
        DEBUG_network("found buffered input on ssl connection");
        return true;
    }

    int rc = 0;
    int rc2 = 0;

        rc = s_checkPending();

        if (rc < 1 ) {
            if (timeout == 0) {  // poll ios handled by calling function
                DEBUG_network("no pending data on ssl connection pending ", rc);
                timedout = true;
                return false;
            } else {
                if ((rc2 = poll(infds, 1, timeout)) == 0) {
                    DEBUG_network("timed out on pending data on ssl connection SSL_pending ", rc);
                    timedout = true;
                    return false;
                }
                if (infds[0].revents & POLLIN) return true;
            }
        }

    DEBUG_network("found data on ssl connection");

    return true;
}


// read a line from the socket
int Socket::getLine(char *buff, int size, int timeout, bool *chopped, bool *truncated)
{
try {
    if (!isssl) {
        return BaseSocket::getLine(buff, size, timeout, chopped, truncated);
    }

    // first, return what's left from the previous buffer read, if anything
    int i = 0;
    if ((bufflen - buffstart) > 0) {
        int tocopy = size - 1;
        if ((bufflen - buffstart) < tocopy)
            tocopy = bufflen - buffstart;
        char *result = (char *)memccpy(buff, buffer + buffstart, '\n', tocopy);
        if (result != NULL) {
            // indicate that a newline was chopped off, if desired
            if (chopped)
                *chopped = true;
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
        //int pend_ret = SSL_has_pending(ssl);
        //DEBUG_network("pending ret ", pend_ret);
        // may need checkForInput here !!
        if (!checkForInput(timeout)) {
            timedout = true;
            return -1;
        }
        bufflen = SSL_read(ssl, buffer, SCK_READ_BUFF_SIZE);

        DEBUG_network("read into buffer; bufflen: ", bufflen);
        if (bufflen < 1) {
            s_errno = SSL_get_error(ssl,bufflen);
            DEBUG_network("read into buffer; s_errno: ", s_errno);

            switch (s_errno) {
                case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_WRITE:
                    if (ssl_poll_wait(s_errno, timeout)) continue;
                    timedout = true;
                    return -1;
                case SSL_ERROR_ZERO_RETURN:  // eof
                    ishup = true;
                    buff[i] = '\0'; // ...terminate string & return what read
                    if (truncated)
                        *truncated = true;
                    return i;
                case SSL_ERROR_SYSCALL:  // happens if other end stops ssl - line may or may not be HUPed
                    ishup = true;
                    return -1;
                default:
                    log_ssl_errors("ssl_read failed %s", "");
                    DEBUG_network("SSL_read failed with error ", SSL_get_error(ssl, bufflen));
                    ishup = true;
                    return -1;
            }
        }
        int tocopy = bufflen;
        if ((i + bufflen) > (size - 1))
            tocopy = (size - 1) - i;
        char *result = (char *)memccpy(buff + i, buffer, '\n', tocopy);
        if (result != NULL) {
            // indicate that a newline was chopped off, if desired
            if (chopped)
                *chopped = true;
            *(--result) = '\0';
            buffstart += (result - (buff + i)) + 1;
            return i + (result - (buff + i));
        }
        i += tocopy;
    }
    // oh dear - buffer end reached before we found a newline
    buff[i] = '\0';
    if (truncated)
        *truncated = true;
    return i;
    } catch (...) {
    return -1;    }
}

// write line to socket
bool Socket::writeString(const char *line)
{
    int l = strlen(line);
    return writeToSocket(line, l, 0, timeout);
}

// write line to socket
bool Socket::writeString(std::string line)
{
    int l = line.length();
    return writeToSocket(line.c_str(), l, 0, timeout);
}

// write data to socket
bool Socket::writeToSocket(const char *buff, int len, unsigned int flags, int timeout)
{
    if (len == 0)   // nothing to write
        return true;
    if (!isssl) {
        return BaseSocket::writeToSocket(buff, len, flags, timeout);
    }

    int actuallysent = 0;
    int sent;
    while (actuallysent < len) {
        DEBUG_network("Ready to write ", len - actuallysent, " bytes");
        ERR_clear_error();
        sent = SSL_write(ssl, buff + actuallysent, len - actuallysent);
        if (sent < 1) {
            s_errno = SSL_get_error(ssl,sent);
            switch (s_errno) {
                case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_WRITE:
                    if (timeout > 0 && ssl_poll_wait(s_errno, timeout)) continue;
                DEBUG_network("Poll timeed out or error");
                    timedout = true;
                    return false;
                case SSL_ERROR_ZERO_RETURN:  // eof
                    DEBUG_network("SSL returns eof on write???");
                    ishup = true;
                    return false;
                default:
                    String serr(s_errno);
                    log_ssl_errors("ssl_write failed - error ",serr.c_str());
                    DEBUG_network("ssl_write failed ", s_errno, " failed to write");
                    ishup = true;
                    return false;
            }

        }
        actuallysent += sent;
    }
    return true;
}

int Socket::readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool ret_part )
{
    if (len == 0)  // nothing to read
         return 0;
    if (!isssl) {
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

//#ifdef DEBUG_LOW
 //   int pend_stat = SSL_has_pending(ssl);
 //   DEBUG_network("has_pending returns ", pend_stat);
//#endif
    bool has_buffer = checkForInput(timeout);

    int rc;
    while (cnt > 0) {
        ERR_clear_error();

        if(!has_buffer) {
            if (timeout > 0) {
                if (!checkForInput(timeout)) {
                    timedout = true;
                    if (len - cnt > 0) {
                        return len - cnt;
                    } else {
                        return -1;
                    }
                }
            }
        } else {
            has_buffer = false;
        }

        ERR_clear_error();
        rc = SSL_read(ssl, buff, cnt);

        if (rc < 1) {
            s_errno = SSL_get_error(ssl,rc);
            DEBUG_network("Error SSL_read ", s_errno);
            switch (s_errno) {
                case SSL_ERROR_WANT_READ:
                   case SSL_ERROR_WANT_WRITE:
                    if (timeout >  0 && ssl_poll_wait(s_errno, timeout)) continue;
                    timedout = true;
                    return -1;
                case SSL_ERROR_ZERO_RETURN:  // eof
                    ishup = true;
                    return len - cnt;
                case SSL_ERROR_SYSCALL:  // ssl stopped at remote end
                    ishup = true;
                    return len - cnt;
                default:
                    log_ssl_errors("ssl_read failed %s", "");
                    DEBUG_network("ssl_read failed", s_errno, " failed to read ",cnt, " bytes");
                    ishup = true;
                    return len - cnt;
            }

        }
        DEBUG_network("SSL read returned ", rc);

        buff += rc;
        cnt -= rc;
        if(ret_part) return len - cnt;
    }

      return len;
}


void Socket::resetChunk() {
    chunk_to_read = 0;
    chunked_trailer = "";
    ieof = false;
}

bool Socket::writeChunk( char *buffout, int len, int timeout){
    std::stringstream stm;
    stm << std::hex << len;
    std::string hexs (stm.str());
    //int lw;
    hexs += "\r\n";
    DEBUG_network("writeChunk  size=", hexs);

    if(!writeString(hexs.c_str())) {
        DEBUG_network(("Error on chunked size write"));
        return false;
    } //else {
      //  DEBUG_network("chunked size write ok");
    //}

    if(!writeToSocket(buffout,len,0,timeout)) {
        DEBUG_network(("Error on chunked data write"));
        return false;
    } //else {
      //  DEBUG_network("chunked data write ok");
    //}
    if(!writeString("\r\n")) {
        DEBUG_network(("Error on chunked line end write"));
        return false;
    } else {
        DEBUG_network("chunked line end write ok");
    }
        return true;
};

bool Socket::writeChunkTrailer( String &trailer) {
    std::string hexs ("0\r\n");
    DEBUG_network("writeChunk trailer size=", hexs);
    if(writeString(hexs.c_str()) && writeToSocket(trailer.c_str(),trailer.length(),0,timeout) && writeString("\r\n"))
        return true;
    return false;
};

int Socket::readChunk( char *buffin, int maxlen, int timeout){
    if (chunk_to_read == 0)     // need to read chunk size
    {
        char size[40];
        ieof = false;
        int len = getLine(size, 38, timeout);
        if (len < 2) {   // min valid length is 2 i.e.  "0\r"
            chunkError = true;
            return -1;
        }
        DEBUG_network("readChunk  size=", size);
        String l = size;
        l.chop();
        String t = l.before(";");
        if (t.length() > 0) {
            if (l.endsWith("; ieof")) {
                ieof = true;
            }
            l = t;
        }
        chunk_to_read = l.hexToInteger();
        DEBUG_network("readChunk  chunk_to_read =", chunk_to_read);
    }

    int clen = chunk_to_read;
    if (clen > maxlen) {
        clen = maxlen;
    }
    int rc = 0;
    DEBUG_network("readChunk  max_read =", clen);

    if(clen == 0) {
        chunked_trailer = "";
        char trailer[32000];
        int len = 3;
        while( len > 2) {
            len = getLine(trailer, 31900, timeout);
            if (len > 2) {
                chunked_trailer += trailer;
                chunked_trailer += "\n";
            }
        }
        return 0;
    }

    if (clen > 0) {
        rc = readFromSocket(buffin, clen, 0, timeout);
        DEBUG_network("readChunk  read ", rc);
        if (rc < 0) {
            chunkError = true;
            return -1;
        }
        chunk_to_read -= rc;
    }
    if (chunk_to_read > 0)    // there is more to read in this chunk - so do not check for trailing \r\n
        return rc;
    char ts[2];
    int len = readFromSocket(ts, 2, 0, timeout);
    if (len == 2 && ts[0] == '\r' && ts[1] == '\n') {
        return rc;
    } else {
        chunkError = true;
        DEBUG_network("readChunk - tail in error");
        return -1;
    }
}

int Socket::loopChunk(int timeout)    // reads chunks and sends back until 0 len chunk or timeout
{
    char buff[32000];
    int tot_size = 0;
    int csize = 1;
    while (csize > 0) {
        csize = readChunk(buff,32000, timeout);
        if (csize == 0)     // end chunk
        {
            if (!writeChunkTrailer(chunked_trailer))
            {
#ifdef CHUNKDEBUG
                std::cerr << thread_id << "loopChunk - error in writing chunk trailer" << std::endl;
#endif
                return -1;

            };
#ifdef CHUNKDEBUG
            std::cerr << thread_id << "loopChunk  tot_size=" << tot_size << std::endl;
#endif
            return tot_size;
        }
        if (!(csize > 0 && writeChunk(buff,csize,timeout))) {
#ifdef CHUNKDEBUG
            std::cerr << thread_id << "loopChunk - error" << std::endl;
#endif
            return -1;
        }
        tot_size += csize;
    }
    return -1;  // should never get here!
}


int Socket::drainChunk(int timeout)    // reads chunks until 0 len chunk or timeout
{
    char buff[32000];
    int tot_size = 0;
    int csize = 1;
    while (csize > 0) {
        csize = readChunk(buff,32000, timeout);
        if (csize < 0) {
#ifdef CHUNKDEBUG
            std::cerr << thread_id << "drainChunk - error" << std::endl;
#endif
            return -1;
        }
        tot_size += csize;
    }
#ifdef CHUNKDEBUG
    std::cerr << thread_id << "drainChunk  tot_size=" << tot_size << std::endl;
#endif
    return tot_size;
}

bool Socket::getIeof() {
    return ieof;
}


bool Socket::ssl_poll_wait(int serr, int timeout) {
  //  if(timeout == 0) {
   //     timedout = true;
    //    return false;
    //}
    int rc;
    s_errno = 0;
    DEBUG_network("sERR ", serr);
    if (serr == SSL_ERROR_WANT_READ) {
        if (isNoRead())
            return false;
        errno = 0;
        rc = poll(infds, 1, timeout);
        if (rc == 0) {
            DEBUG_network("poll returned 0");
            timedout = true;
            return false;   //timeout
        }
        timedout = false;
        if (rc < 0) {
            DEBUG_network("poll returned ", s_errno);
            s_errno = errno;
            sockerr = true;
            return false;
        }
        if (infds[0].revents & POLLHUP) {
            DEBUG_network("poll returned HUP");
            ishup = true;
        }
        if ((infds[0].revents & ( POLLIN))) {
            return true;
        }
        sockerr = true;
        return false;   // must be POLLERR or POLLNVAL
    } else if(serr == SSL_ERROR_WANT_WRITE) { //must be SSL_ERROR_WANT_WRITE
        if (isNoWrite())
            return false;
        errno = 0;
        rc = poll(outfds, 1, timeout);
        if (rc == 0) {
            timedout = true;
            DEBUG_network("poll returned 0");
            return false;   //timeout
        }
        timedout = false;
        if (rc < 0) {
            s_errno = errno;
            DEBUG_network("poll returned ", s_errno);
            sockerr = true;
            return false;
        }
        if (outfds[0].revents & POLLHUP) {
            ishup = true;
            DEBUG_network("poll returned HUP");
        }
        if ((outfds[0].revents & ( POLLOUT))) {
            return true;
        }
    }
    return false;
}

short int Socket::get_wait_flag(bool write_flag) {
    if (!isssl)
        return BaseSocket::get_wait_flag(write_flag);
    if(timedout) {
        if (s_errno == SSL_ERROR_WANT_READ) {
            timedout = false;
            return POLLIN;
        } else if (s_errno == SSL_ERROR_WANT_WRITE) {
            timedout = false;
            return POLLOUT;
        }
    }
    return POLLIN;
}

void Socket::setClientAddr(std::string ip, int port) {
    client_addr = ip;
    client_port = port;
}

bool Socket::s_checkPending() {
    if(s_checkShutdown()&SSL_RECEIVED_SHUTDOWN) {
        DEBUG_network("SSL shudown in progress - returning false");
        return (s_pending = false);
    }
    s_pending = SSL_pending(ssl);
    DEBUG_network("SSL_pending gives ", s_pending);
#ifndef  LIBRESSL_VERSION_NUMBER
    s_prev_has_pending = s_has_pending;
    s_has_pending = SSL_has_pending(ssl);
    DEBUG_network("SSL_has_pending gives ", s_has_pending);
    s_pending = s_pending || (s_has_pending && !s_prev_has_pending);
#endif
    DEBUG_network("Returning ", s_pending);
    return s_pending;
}

int Socket::s_checkShutdown() {
    return SSL_get_shutdown(ssl);
}
