// Socket class - implements BaseSocket for INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "Socket.hpp"

#include <string.h>
#include <syslog.h>
#include <csignal>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <stdexcept>
#include <cerrno>
#include <unistd.h>
#include <netinet/tcp.h>

#ifdef __SSLMITM
#include "openssl/x509v3.h"
#include "openssl/asn1.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "String.hpp"
#include "CertificateAuthority.hpp"
#endif

#ifdef __SSLMITM
extern bool reloadconfig;

#ifndef X509_V_FLAG_TRUSTED_FIRST
#warning "openssl X509_V_FLAG_TRUSTED_FIRST not available, certificate chain creation will be unreliable and will fail on some sites"
#warning "To fix install a later version of openssl"
#define X509_V_FLAG_TRUSTED_FIRST 0
#endif
#endif

// IMPLEMENTATION

// constructor - create an INET socket & clear address structs
Socket::Socket()
{
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
            int res = setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));

        my_port = 0;

#ifdef __SSLMITM
        ssl = NULL;
        ctx = NULL;
        isssl = false;
        issslserver = false;
#else
        isssl = false;
#endif
    }
}

// create socket from pre-existing FD (address structs will be invalid!)
Socket::Socket(int fd)
    : BaseSocket(fd)
{
    memset(&my_adr, 0, sizeof my_adr);
    memset(&peer_adr, 0, sizeof peer_adr);
    my_adr.sin_family = AF_INET;
    peer_adr.sin_family = AF_INET;
    peer_adr_length = sizeof(struct sockaddr_in);
    int f = 1;

    int res = setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, &f, sizeof(int));
    if (res < 0) s_errno = errno;
    my_port = 0;

#ifdef __SSLMITM
    ssl = NULL;
    ctx = NULL;
    isssl = false;
    issslserver = false;
#else
    isssl = false;
#endif
}

// create socket from pre-existing FD, storing local & remote IPs
Socket::Socket(int newfd, struct sockaddr_in myip, struct sockaddr_in peerip)
    : BaseSocket(newfd)
{
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

#ifdef __SSLMITM
    ssl = NULL;
    ctx = NULL;
    isssl = false;
    issslserver = false;
#else
    isssl = false;
#endif
}

// find the ip to which the client has connected
std::string Socket::getLocalIP()
{
    return inet_ntoa(my_adr.sin_addr);
}

// find the ip of the client connecting to us
std::string Socket::getPeerIP()
{
    return inet_ntoa(peer_adr.sin_addr);
}

// find the port of the client connecting to us
int Socket::getPeerSourcePort()
{
    return ntohs(peer_adr.sin_port);
}
int Socket::getPort()
{
    return my_port;
}
void Socket::setPort(int port)
{
    my_port = port;
}

// return the address of the client connecting to us
unsigned long int Socket::getPeerSourceAddr()
{
    return (unsigned long int)ntohl(peer_adr.sin_addr.s_addr);
}

// close connection & wipe address structs
void Socket::reset()
{
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

#ifdef __SSLMITM
    if (isssl) {
        stopSsl();
    }
#endif //__SSLMITM
}

// connect to given IP & port (following default constructor)
int Socket::connect(const std::string &ip, int port)
{
    //if (sck > -1)  reset();   // just in case this is called with socket still open
    reset();   // do it anyway as we need sck to be allocated

    if (sck < 0) // socket creation error
    { return -1;
    }

    int len = sizeof my_adr;
    peer_adr.sin_port = htons(port);
    inet_aton(ip.c_str(), &peer_adr.sin_addr);
    my_port = port;
    // make non-blocking for connect only so that we can timeout connect
    fcntl(sck, F_SETFL, O_NONBLOCK);
    s_errno = 0;
    errno = 0;
    int ret = ::connect(sck, (struct sockaddr *)&peer_adr, len);
    if (ret < 0 && errno == EINPROGRESS) ret = 0;
    else s_errno = errno;
    if (ret == 0){
        int rc = poll(outfds,1,timeout);
        if (rc == 0) {
            timedout = true;
            ret = -1;
        }
        else if (rc < 0) {
            s_errno = errno;
            ret = -1;
        }
        else {  // ret == 1
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
    fcntl(sck, F_SETFL, 0);  // make blocking again
    if (ret < 0) close();
    return ret;
}
// bind socket to given port
int Socket::bind(int port)
{
    int len = sizeof my_adr;
    int i = 1;

    int res = setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_port = port;

    return ::bind(sck, (struct sockaddr *)&my_adr, len);
}

// bind socket to given port & IP
int Socket::bind(const std::string &ip, int port)
{
    int len = sizeof my_adr;
    int i = 1;

    int res = setsockopt(sck, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));

    my_adr.sin_port = htons(port);
    my_adr.sin_addr.s_addr = inet_addr(ip.c_str());
    my_port = port;

    return ::bind(sck, (struct sockaddr *)&my_adr, len);
}

// accept incoming connections & return new Socket
Socket *Socket::accept()
{
    peer_adr_length = sizeof(struct sockaddr_in);
    s_errno = 0;
    errno = 0;
//    int newfd = this->baseAccept((struct sockaddr *)&peer_adr, &peer_adr_length);
    int newfd = ::accept(sck,( struct sockaddr *)&peer_adr, &peer_adr_length);

    if (newfd > 0) {
        Socket *s = new Socket(newfd, my_adr, peer_adr);
        s->setPort(my_port);
        return s;
    } else {
        s_errno = errno;
        return NULL;
    }
}

#ifdef __SSLMITM
//use this socket as an ssl client
int Socket::startSslClient(const std::string &certificate_path, String hostname)
{
    if (isssl) {
        stopSsl();
    }

    ERR_clear_error();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
//needed to get the errors when creating ctx
//ERR_print_errors_fp(stderr);
//printerr(strerror(errno));
#ifdef DGDEBUG
        //syslog(LOG_ERR, "error creating ssl context\n");
        std::cout << "Error ssl context is null (check that openssl has been inited)" << std::endl;
#endif
        log_ssl_errors("Error ssl context is null for %s", hostname.c_str());
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
#ifdef DGDEBUG
            std::cout << "couldnt load certificates" << std::endl;
#endif
            log_ssl_errors("couldnt load certificates from %s", certificate_path.c_str());
            //tidy up
            SSL_CTX_free(ctx);
            ctx = NULL;
            return -2;
        }
    } else if (!SSL_CTX_set_default_verify_paths(ctx)) //use default if no certPpath given
    {
#ifdef DGDEBUG
        std::cout << "couldnt load certificates" << std::endl;
#endif
            log_ssl_errors("couldnt load default certificates for %s", hostname.c_str());
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
        //X509_VERIFY_PARAM_free(x509_param);
            SSL_CTX_free(ctx);
            ctx = NULL;
        return -2;
    }

    ERR_clear_error();
    if (!X509_VERIFY_PARAM_set_flags(x509_param, X509_V_FLAG_TRUSTED_FIRST)) {
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

    X509_VERIFY_PARAM_free(x509_param);     // try not freeing this as SSL_CTX_free seems to be ring to free it

    //hand socket over to ssl lib
    ERR_clear_error();
    ssl = SSL_new(ctx);
    SSL_set_options(ssl, SSL_OP_ALL);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_connect_state(ssl);

    //fcntl(this->getFD() ,F_SETFL, O_NONBLOCK);
    SSL_set_fd(ssl, this->getFD());
    SSL_set_tlsext_host_name(ssl, hostname.c_str());

    //make io non blocking as select wont tell us if we can do a read without blocking
    //BIO_set_nbio(SSL_get_rbio(ssl),1l);
    //BIO_set_nbio(SSL_get_wbio(ssl),1l);
    ERR_clear_error();
    int rc = SSL_connect(ssl);
    if (rc < 0) {
        //ERR_print_errors_fp(stderr);
        log_ssl_errors("ssl_connect failed to %s", hostname.c_str());
#ifdef DGDEBUG
        std::cout << "ssl_connect failed with error " << SSL_get_error(ssl, rc) << std::endl;
#endif
        // tidy up
        SSL_free(ssl);
        ssl = NULL;
        SSL_CTX_free(ctx);
        ctx = NULL;
        return -3;
    }

    //should be safer to do this last as nothing will ever try to use a ssl socket that isn't fully setup
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
#ifdef DGDEBUG
    std::cout << "ssl stopping" << std::endl;
#endif
    if(!isssl) return;

    isssl = false;

    if (ssl != NULL) {
        if (issslserver) {
#ifdef DGDEBUG
            std::cout << "this is a server connection" << std::endl;
            if (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) {
                std::cout << "SSL_SENT_SHUTDOWN IS SET" << std::endl;
            }
            if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
                std::cout << "SSL_RECIEVED_SHUTDOWN IS SET" << std::endl;
            }
            std::cout << "calling 1st ssl shutdown" << std::endl;
#endif
            if (!SSL_shutdown(ssl)) {
#ifdef DGDEBUG
                std::cout << "need to call SSL shutdown again" << std::endl;
                if (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) {
                    std::cout << "SSL_SENT_SHUTDOWN IS SET" << std::endl;
                }
                if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
                    std::cout << "SSL_RECIEVED_SHUTDOWN IS SET" << std::endl;
                }
                std::cout << "Discarding extra data from client" << std::endl;
#endif

                //SSL_set_quiet_shutdown(ssl,1);
                //SSL_shutdown(ssl);
                shutdown(SSL_get_fd(ssl), SHUT_WR);
                char junk[1024];
                readFromSocket(junk, sizeof(junk), 0, 5);
#ifdef DGDEBUG
                std::cout << "done" << std::endl;
#endif
            }
        } else {
#ifdef DGDEBUG
            std::cout << "this is a client connection" << std::endl;
            if (SSL_get_shutdown(ssl) & SSL_SENT_SHUTDOWN) {
                std::cout << "SSL_SENT_SHUTDOWN IS SET" << std::endl;
            }
            if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
                std::cout << "SSL_RECIEVED_SHUTDOWN IS SET" << std::endl;
            }
            std::cout << "calling ssl shutdown" << std::endl;
#endif
            SSL_shutdown(ssl);
#ifdef DGDEBUG
            std::cout << "done" << std::endl;
#endif
        }

        SSL_free(ssl);
        ssl = NULL;
    }

    issslserver = false;
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }
}

//check that everything in this certificate is correct apart from the hostname
long Socket::checkCertValid()
{
    //check we have a certificate
    X509 *peerCert = SSL_get_peer_certificate(ssl);
    if (peerCert == NULL) {
        return -1;
    }
    X509_free(peerCert);
    return SSL_get_verify_result(ssl);
}

//check the common name and altnames of a certificate against hostname
int Socket::checkCertHostname(const std::string &_hostname)
{
    String hostname = _hostname;
    bool matched = false;
    bool hasaltname = false;

    X509 *peercertificate = SSL_get_peer_certificate(ssl);
    if (peercertificate == NULL) {
#ifdef DGDEBUG
        std::cout << "unable to get certificate for " << hostname << std::endl;
#endif
        return -1;
    }
    //force to lower case as domain names are not case sensetive
    hostname.toLower();

#ifdef DGDEBUG
    std::cout << "checking certificate" << hostname << std::endl;
    std::cout << "Checking hostname against subjectAltNames" << std::endl;
#endif

    //check the altname extension for additional valid names
    STACK_OF(GENERAL_NAME) *gens = NULL;
    gens = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(peercertificate, NID_subject_alt_name, 0, 0);
    int r = sk_GENERAL_NAME_num(gens);
    for (int i = 0; i < r; ++i) {
        const GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);

        //if its not a dns entry we really don't care about it
        if (gn->type != GEN_DNS) {
            continue;
        }

        //only mark hasaltname as true if it has a DNS altname
        hasaltname = true;

        //an ASN1_IA5STRING is a define of an ASN1_STRING so we can do it this way
        unsigned char *nameutf8;
        int len = ASN1_STRING_to_UTF8(&nameutf8, gn->d.ia5);
        if (len < 0) {
            break;
        }

        String altname = std::string((char *)nameutf8, len);
        OPENSSL_free(nameutf8);

        //force to lower case as domain names are not case sensetive
        altname.toLower();

#ifdef DGDEBUG
        std::cout << "checking against alt name " << altname << std::endl;
#endif

        if (hostname.compare(altname) == 0) {
            matched = true;
            break;
        } else if (altname.startsWith("*.")) {
#ifdef DGDEBUG
            std::cout << "Wildcard certificate is in use" << std::endl;
#endif
            altname = altname.after("*"); // need to keep the "."
            if (hostname.endsWith(altname)) {
                matched = true;
                break;
            }
        }
    }
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

    if (matched) {
        X509_free(peercertificate);
        return 0;
    } else if (hasaltname) {
        X509_free(peercertificate);
        return -1;
    }

#ifdef DGDEBUG
    std::cout << "checking hostname against the following common names" << std::endl;
#endif

    X509_NAME *name = X509_get_subject_name(peercertificate);

    int current_entry = -1;
    while (1) {

        //get the common name from the certificate
        current_entry = X509_NAME_get_index_by_NID(name, NID_commonName, current_entry);
        if (current_entry == -1) {
            //if we've run out of common names then move on to altnames
            break;
        }

        //X509_NAME_get_entry result must not be freed
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, current_entry);

        ASN1_STRING *asn1name = X509_NAME_ENTRY_get_data(entry);

        unsigned char *nameutf8;
        int len = ASN1_STRING_to_UTF8(&nameutf8, asn1name);
        if (len < 0) {
            break;
        }
        String commonname = std::string((char *)nameutf8, len);

        OPENSSL_free(nameutf8);
        //ASN1_STRING_free(asn1name);

        //force to lower case as domain names are not case sensetive
        commonname.toLower();

#ifdef DGDEBUG
        std::cout << "checking against common name " << commonname << std::endl;
#endif

        //compare the hostname to the common name
        if (hostname.compare(commonname) == 0) {
            matched = true;
            break;
        }
        //see if its a wildcard certificate
        else if (commonname.startsWith("*.")) {
#ifdef DGDEBUG
            std::cout << "Wildcard certificate is in use" << std::endl;
#endif
            commonname = commonname.after("*"); // need to keep the "."

            if (hostname.endsWith(commonname)) {
                matched = true;
                break;
            }
        }
    }

    if (matched) {
        X509_free(peercertificate);
        return 0;
    }

    return -1;
}

void Socket::close()
{
    if (isssl) {
        stopSsl();
    }
    BaseSocket::close();
}
#endif //__SSLMITM

#ifdef __SSLMITM
//use this socket as an ssl server
int Socket::startSslServer(X509 *x, EVP_PKEY *privKey, std::string &set_cipher_list)
{

    if (isssl) {
        stopSsl();
    }

    // set ssl to NULL
    ssl = NULL;

    //setup the ssl server ctx
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
#ifdef DGDEBUG
        //syslog(LOG_ERR, "error creating ssl context\n");
        std::cout << "Error ssl context is null (check that openssl has been inited)" << std::endl;
#endif
        return -1;
    }

    //set the timeout to match firefox
    if (SSL_CTX_set_timeout(ctx, 130l) < 1) {
        return -1;
    }

    //set the ctx to use the certificate
    if (SSL_CTX_use_certificate(ctx, x) < 1) {
#ifdef DGDEBUG
        //syslog(LOG_ERR, "error creating ssl context\n");
        std::cout << "Error using certificate" << std::endl;
#endif
        return -1;
    }

    if (set_cipher_list.length() > 0)
        SSL_CTX_set_cipher_list(ctx, set_cipher_list.c_str());

    //set the ctx to use the private key
    if (SSL_CTX_use_PrivateKey(ctx, privKey) < 1) {
#ifdef DGDEBUG
        //syslog(LOG_ERR, "error creating ssl context\n");
        std::cout << "Error using private key" << std::endl;
#endif
        return -1;
    }

    //setup the ssl session
    ERR_clear_error();
    ssl = SSL_new(ctx);
    SSL_set_options(ssl, SSL_OP_ALL);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_accept_state(ssl);

    ERR_clear_error();
    SSL_set_fd(ssl, this->getFD());

    //make io non blocking as select wont tell us if we can do a read without blocking

    ERR_clear_error();
    if (SSL_accept(ssl) < 0) {
#ifdef DGDEBUG
        //syslog(LOG_ERR, "error creating ssl context\n");
        std::cout << "Error accepting ssl connection" << std::endl;
#endif
        log_ssl_errors("ssl_accept failed to client %s", "");
        stopSsl();
        return -1;
    }

    ERR_clear_error();
    if (SSL_do_handshake(ssl) < 0) {
#ifdef DGDEBUG
        //syslog(LOG_ERR, "error creating ssl context\n");
        std::cout << "Error doing ssl handshake" << std::endl;
#endif
        log_ssl_errors("ssl_handshake failed to client %s", "");
        stopSsl();
        return -1;
    }
    isssl = true;
    issslserver = true;
    return 0;
}

//modify all of these to use SSL_write(ssl,buf,len) and SSL_read(ssl,buf,buflen)

//have to replace checkforinput as the ssl session will constantly generate traffic even if theres no real data
// non-blocking check to see if there is data waiting on socket
bool Socket::checkForInput()
{
    if (!isssl) {
        return BaseSocket::checkForInput();
    }
#ifdef DGDEBUG
    std::cout << "checking for input on ssl connection (non blocking)" << std::endl;
#endif
    if ((bufflen - buffstart) > 0) {
#ifdef DGDEBUG
        std::cout << "found input on ssl connection" << std::endl;
#endif
        return true;
    }

    if (!BaseSocket::checkForInput())
        return false;

    //see if we can do an ssl read of 1 byte
//    char buf[1];

    //int rc = SSL_peek(ssl, buf, 1);
    int rc = SSL_pending(ssl);

    if (rc < 1) {
#ifdef DGDEBUG
        std::cout << "no pending data on ssl connection SSL_pending " << rc << std::endl;
#endif
        return false;
    }

#ifdef DGDEBUG
    std::cout << "found data on ssl connection" << std::endl;
#endif

    return true;
}

bool Socket::bcheckForInput(int timeout)
{
    if (!isssl) {
        return BaseSocket::bcheckForInput(timeout);
    }
    return true;
}


bool Socket::readyForOutput()
{
    //if (!isssl) {
        return BaseSocket::readyForOutput();
    //}

    //can't do this on a blocking ssl socket as far as i can work out

    //return true;
}

bool Socket::breadyForOutput(int timeout)
{
    //if (!isssl) {
        return BaseSocket::breadyForOutput(timeout);
    //}
    //return true;
}


// read a line from the socket, can be told to break on config reloads
int Socket::getLine(char *buff, int size, int timeout, bool honour_reloadconfig, bool *chopped, bool *truncated) throw(std::exception)
{
    if (!isssl) {
        return BaseSocket::getLine(buff, size, timeout, honour_reloadconfig, chopped, truncated);
    }
#ifdef DGDEBUG
		std::cout << "in getline (SSL): timeout: " << timeout << " size: " << size << std::endl;

#endif

    // first, return what's left from the previous buffer read, if anything
    int i = 0;
    if ((bufflen - buffstart) > 0) {
#ifdef DGDEBUG
		std::cout << "getline(ssl) data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif
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
 //       try {
 //            checkForInput(timeout, honour_reloadconfig);
 //       } catch (std::exception &e) {
//            throw std::runtime_error(std::string("Can't read from socket: ") + strerror(errno)); // on error
 //       }
 //       if( bcheckSForInput(timeout))
            bufflen = SSL_read(ssl, buffer, 4096);
#ifdef DGDEBUG
std::cout << "getline (SSL) read into buffer; bufflen: " << bufflen <<std::endl;
#endif
        if (bufflen < 0) {
  //          if (errno == EINTR ) {
   //             continue;
    //        }

#ifdef DGDEBUG
            std::cerr << "SSL_read failed with error " << SSL_get_error(ssl, bufflen) << std::endl;
#endif
            log_ssl_errors("ssl_read failed %s", "");
            return -1;
//            throw std::runtime_error(std::string("Can't read from ssl socket")); //strerror(errno));  // on error
        }
        //if socket closed...
        if (bufflen == 0) {
            buff[i] = '\0'; // ...terminate string & return what read
            if (truncated)
                *truncated = true;
#ifdef DGDEBUG
            if (truncated)
            	std::cout << "Getline(SSL) truncated buffer end reached before we found a newline: bufflen == 0" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
            return i;
        }
        int tocopy = bufflen;
        if ((i + bufflen) > (size - 1))
            tocopy = (size - 1) - i;
        char *result = (char *)memccpy(buff + i, buffer, '\n', tocopy);
        if (result != NULL) {
#ifdef DGDEBUG
        std::cout << "getLine result (SSL): " << result << std::endl;
#endif
            // indicate that a newline was chopped off, if desired
            if (chopped)
                *chopped = true;
            *(--result) = '\0';
            buffstart += (result - (buff + i)) + 1;
            return i + (result - (buff + i));
        }
        i += tocopy;
#ifdef DGDEBUG
            std::cout << "getLine(SSL) buffer =: " << buff[i] << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    }
    // oh dear - buffer end reached before we found a newline
    buff[i] = '\0';
    if (truncated)
        *truncated = true;
#ifdef DGDEBUG
    	if (truncated)
            std::cout << "Getline(SSL) truncated buffer end reached before we found a newline: " << buff  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
    return i;
}

// write line to socket
bool Socket::writeString(const char *line) //throw(std::exception)
{
    int l = strlen(line);
    return writeToSocket(line, l, 0, timeout);
//    if (!writeToSocket(line, l, 0, timeout)) {
 //       throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));
    //}
}


// write data to socket - can be told not to do an initial readyForOutput, and to break on config reloads
bool Socket::writeToSocket(const char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
    if (!isssl) {
        return BaseSocket::writeToSocket(buff, len, flags, timeout, check_first, honour_reloadconfig);
    }

    int actuallysent = 0;
    int sent;
    while (actuallysent < len) {
       if (check_first) {
    //        try {
                if(!breadyForOutput(timeout))
                   return false;
     //       } catch (std::exception &e) {
      //          return false;
       //     }
        }
        ERR_clear_error();
        sent = SSL_write(ssl, buff + actuallysent, len - actuallysent);
        if (sent < 0) {
    //        if (errno == EINTR ) {
    //            continue; // was interupted by signal so restart
    //        }
            s_errno = errno;
            log_ssl_errors("ssl_write failed %s", "");
            return false;
        }
        if (sent == 0) {
            ishup = true;
            return false; // other end is closed
        }
        actuallysent += sent;
    }
    return true;
}

// read a specified expected amount and return what actually read
int Socket::readFromSocketn(char *buff, int len, unsigned int flags, int timeout)
{
    return readFromSocket(buff, len, flags, timeout, true, false);


#ifdef NODEF
    if (!isssl) {
        return BaseSocket::readFromSocketn(buff, len, flags, timeout);
    }

    int cnt, rc;
    cnt = len;

    // first, return what's left from the previous buffer read, if anything
    if ((bufflen - buffstart) > 0) {
#ifdef DGDEBUG
        std::cout << "Socket::readFromSocketn: data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
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
    //    try {
    //        bcheckSForInput(timeout);        //  this may be wrong - why is data not being read into socket buffer????
    //    } catch (std::exception &e) {
     //       return -1;
     //   }
        ERR_clear_error();
        rc = SSL_read(ssl, buff, cnt);
#ifdef DGDEBUG
        std::cout << "ssl read said: " << rc << std::endl;
#endif

        if (rc < 0) {
       //     if (errno == EINTR) {
         //       continue;
           // }
            log_ssl_errors("ssl_read failed %s", "");
           s_errno = errno;
            return -1;
        }
        if (rc == 0) { // eof
             ishup = true;
            return len - cnt;
        }
        buff += rc;
        cnt -= rc;
    }
    return len;
#endif
}

// read what's available and return error status - can be told not to do an initial checkForInput, and to break on reloads
int Socket::readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool check_first, bool honour_reloadconfig)
{
    if (!isssl) {
        return BaseSocket::readFromSocket(buff, len, flags, timeout, check_first, honour_reloadconfig);
    }

    // first, return what's left from the previous buffer read, if anything
    int cnt = len;
    int tocopy = 0;
    if ((bufflen - buffstart) > 0) {
#ifdef DGDEBUG
        std::cout << "Socket::readFromSocket(ssl): data already in buffer; bufflen: " << bufflen << " buffstart: " << buffstart << std::endl;
#endif
        tocopy = len;
        if ((bufflen - buffstart) < len)
            tocopy = bufflen - buffstart;
        memcpy(buff, buffer + buffstart, tocopy);
        cnt -= tocopy;
        buffstart += tocopy;
        buff += tocopy;
        if (cnt == 0)
            return len;
    }

#ifdef DGDEBUG
        std::cout << "Socket::readFromSocket(ssl): now entering loop to read: " << cnt << " bytes: " << std::endl;
#endif
    int rc;
    while (cnt > 0) {
 //   if (check_first) {
//#ifdef DGDEBUG
//       std::cout << "Socket::readFromSocket(ssl): before bcheckSForInput timeout is: " << timeout  << std::endl;
//#endif
//          if(!bcheckSForInput(timeout))
  //          return -1;
//#ifdef DGDEBUG
//        std::cout << "Socket::readFromSocket(ssl): after bcheckSForInput OK return: " << std::endl;
//#endif
  // }
//    while (true)
        bool inbuffer;
#ifdef DGDEBUG
        std::cout << "Socket::readFromSocket(ssl): before SSL_read: "  << std::endl;
#endif
        ERR_clear_error();
       if (true) {     // was if(cnt > 4095)
            inbuffer = false;
           rc = SSL_read(ssl, buff, cnt);        //  data larger than SSL buffer so ok to read directly into output buffer
        } else {
            inbuffer = true;
           rc = SSL_read(ssl, buffer, 4096);   // read into socket buffer to flush SSL buffer
        }

        if (rc < 0) {
            s_errno = errno;
            log_ssl_errors("ssl_read failed %s", "");
#ifdef DGDEBUG
        std::cout << "ssl_read failed" << s_errno << " failed to read " << cnt << " bytes" << std::endl;
#endif
            rc = 0;
        }
        if (rc == 0) { // eof
             ishup = true;
             return len - cnt;
             }

        if (inbuffer) {
#ifdef DGDEBUG
        std::cout << "Inbuffer SSL read to return " << cnt << " bytes" << std::endl;
#endif

           buffstart = 0;
           bufflen = rc;
           if ((bufflen - buffstart) > 0) {
              tocopy = cnt;
              if ((bufflen - buffstart) < cnt)
              tocopy = bufflen - buffstart;
              memcpy(buff, buffer + buffstart, tocopy);
              cnt -= tocopy;
              buffstart += tocopy;
              buff += tocopy;
#ifdef DGDEBUG
        std::cout << "Inbuffer SSL read returned " << tocopy << " bytes" << std::endl;
#endif
           }
         } else {
        buff += rc;
        cnt -= rc;
         }
 //       break;
#ifdef DGDEBUG
        std::cout << "Still to read (SSL) " << cnt << " bytes" << std::endl;
#endif
    }

//    return rc + tocopy;
      return len;
}

#endif //__SSLMITM
