// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
//#include "NaughtyFilter.hpp"
//#include "StoryBoard.hpp"
#include "ConnectionHandler.hpp"
#include "DataBuffer.hpp"
#include "UDSocket.hpp"
//#include "Auth.hpp"
#include "FDTunnel.hpp"
#include "BackedStore.hpp"
#include "Queue.hpp"
#include "ImageContainer.hpp"
#include "FDFuncs.hpp"
#include <signal.h>
#include <arpa/nameser.h>
#include <resolv.h>

#ifdef __SSLMITM
#include "CertificateAuthority.hpp"
#endif //__SSLMITM

#include <syslog.h>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <algorithm>
#include <netdb.h>
#include <cstdlib>
#include <unistd.h>
#include <sys/time.h>
#include <strings.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <istream>
#include <sstream>
#include <memory>

#ifdef ENABLE_ORIG_IP
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#endif

#ifdef __SSLMITM
#include "openssl/ssl.h"
#include "openssl/x509v3.h"
#include "String.hpp"
#endif

// GLOBALS
extern OptionContainer o;
extern bool is_daemonised;
extern std::atomic<int> ttg;
//bool reloadconfig = false;
// If a specific debug line is needed
//thread_local int thread_id = 0;
extern thread_local std::string thread_id;


// IMPLEMENTATION

ConnectionHandler::ConnectionHandler()
    : clienthost(NULL) {
     //ch_isiphost.comp(",*[a-z|A-Z].*");

    // initialise SBauth structure
    SBauth.filter_group = 0;
    SBauth.is_authed = false;
    SBauth.user_name = "";
}


// Custom exception class for POST filtering errors
class postfilter_exception : public std::runtime_error
{
    public:
    postfilter_exception(const char *const &msg)
        : std::runtime_error(msg){};
};

//
// URL cache funcs
//

// check the URL cache to see if we've already flagged an address as clean
bool wasClean(HTTPHeader &header, String &url, const int fg)
{
   return false;   // this function needs rewriting always return false
}

// add a known clean URL to the cache
void addToClean(String &url, const int fg)
{
    return ;   // this function needs rewriting
}

//
// ConnectionHandler class
//


void ConnectionHandler::cleanThrow(const char *message, Socket &peersock, Socket &proxysock)
{
if (o.logconerror)
{
   int peerport = peersock.getPeerSourcePort();

    std::string peer_ip = peersock.getPeerIP();

    int err = peersock.getErrno();

    if (peersock.isTimedout())
        syslog(LOG_INFO, "%d %s Client at %s Connection timedout - errno: %d", peerport, message, peer_ip.c_str(), err);
    else if (peersock.isHup())
        syslog(LOG_INFO, "%d %s Client at %s has disconnected - errno: %d", peerport, message, peer_ip.c_str(), err);
     else if (peersock.sockError())
        syslog(LOG_INFO, "%d %s Client at %s Connection socket error - errno: %d", peerport, message, peer_ip.c_str(),err);
    else if (peersock.isNoRead())
        syslog(LOG_INFO, "%d %s cant read Client Connection at %s - errno: %d ", peerport, message, peer_ip.c_str(),err);
    else if (peersock.isNoWrite())
        syslog(LOG_INFO, "%d %s cant write Client Connection  at %s - errno: %d ", peerport, message, peer_ip.c_str(),err);
    else if (peersock.isNoOpp())
        syslog(LOG_INFO, "%d %s Client Connection at %s is no-op - errno: %d", peerport, message, peer_ip.c_str(),err);
    else
        syslog(LOG_INFO, "%d %s Client Connection at %s problem - errno: %d", peerport, message, peer_ip.c_str(),err);

    err = proxysock.getErrno();
    if (proxysock.isTimedout())
        syslog(LOG_INFO, "%d %s proxy timedout - errno: %d", peerport, message, err);
    else if (proxysock.isHup())
        syslog(LOG_INFO, "%d %s proxy has disconnected - errno: %d", peerport, message, err);
    else if (proxysock.sockError())
        syslog(LOG_INFO, "%d %s proxy socket error - errno: %d", peerport, message, err);
    else if (proxysock.isNoRead())
        syslog(LOG_INFO, "%d %s cant read proxy Connection - errno: %d ", peerport, message, err);
    else if (proxysock.isNoWrite())
        syslog(LOG_INFO, "%d %s cant write proxy Connection  - errno: %d", peerport, message, err);
    else if (proxysock.isNoOpp())
        syslog(LOG_INFO, "%d %s proxy Connection is no-op - errno: %d", peerport, message, err);
    else
        syslog(LOG_INFO, "%d %s proxy Connection problem - errno: %d", peerport, message, err);
}
    if (proxysock.isNoOpp())
        proxysock.close();
    throw std::exception();
}

void ConnectionHandler::cleanThrow(const char *message, Socket &peersock ) {
    if (o.logconerror)
    {
        int peerport = peersock.getPeerSourcePort();
        std::string peer_ip = peersock.getPeerIP();
        int err = peersock.getErrno();

        if (peersock.isTimedout())
            syslog(LOG_INFO, "%d %s Client at %s Connection timedout - errno: %d", peerport, message, peer_ip.c_str(), err);
        else if (peersock.isHup())
            syslog(LOG_INFO, "%d %s Client at %s has disconnected - errno: %d", peerport, message, peer_ip.c_str(), err);
        else if (peersock.sockError())
            syslog(LOG_INFO, "%d %s Client at %s Connection socket error - errno: %d", peerport, message, peer_ip.c_str(),err);
        else if (peersock.isNoRead())
            syslog(LOG_INFO, "%d %s cant read Client Connection at %s - errno: %d ", peerport, message, peer_ip.c_str(),err);
        else if (peersock.isNoWrite())
            syslog(LOG_INFO, "%d %s cant write Client Connection  at %s - errno: %d ", peerport, message, peer_ip.c_str(),err);
        else if (peersock.isNoOpp())
            syslog(LOG_INFO, "%d %s Client Connection is no-op - errno: %d", peerport, message, err);
        else
            syslog(LOG_INFO, "%d %s Client Connection at %s problem - errno: %d", peerport, message, peer_ip.c_str(),err);
    }
    throw std::exception();
}

// perform URL encoding on a string
std::string ConnectionHandler::miniURLEncode(const char *s)
{
    std::string encoded;
    char *buf = new char[3];
    unsigned char c;
    for (int i = 0; i < (signed)strlen(s); i++) {
        c = s[i];
        // allowed characters in a url that have non special meaning
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            encoded += c;
            continue;
        }
        // all other characters get encoded
        sprintf(buf, "%02x", c);
        encoded += "%";
        encoded += buf;
    }
    delete[] buf;
    return encoded;
}

// create a temporary bypass URL for the banned page
String ConnectionHandler::hashedURL(String *url, int filtergroup, std::string *clientip, bool infectionbypass)
{
    // filter/virus bypass hashes last for a certain time only
    //String timecode(time(NULL) + (infectionbypass ? (*ldl->fg[filtergroup]).infection_bypass_mode : (*ldl->fg[filtergroup]).bypass_mode));
    String timecode(time(NULL) + (infectionbypass ? (*ldl->fg[filtergroup]).infection_bypass_mode : (*ldl->fg[filtergroup]).bypass_mode));
    // use the standard key in normal bypass mode, and the infection key in infection bypass mode
    String magic(infectionbypass ? ldl->fg[filtergroup]->imagic.c_str() : ldl->fg[filtergroup]->magic.c_str());
    magic += clientip->c_str();
    magic += timecode;
    String res(infectionbypass ? "GIBYPASS=" : "GBYPASS=");
    if (!url->after("://").contains("/")) {
        String newurl((*url));
        newurl += "/";
        res += newurl.md5(magic.toCharArray());
    } else {
        res += url->md5(magic.toCharArray());
    }
    res += timecode;
    return res;
}

// create temporary bypass cookie
String ConnectionHandler::hashedCookie(String *url, const char *magic, std::string *clientip, int bypasstimestamp)
{
    String timecode(bypasstimestamp);
    String data(magic);
    data += clientip->c_str();
    data += timecode;
    String res(url->md5(data.toCharArray()));
    res += timecode;

#ifdef DGDEBUG
    std::cerr << thread_id << " -hashedCookie=" << res << std::endl;
#endif
    return res;
}


// send a file to the client - used during bypass of blocked downloads
off_t ConnectionHandler::sendFile(Socket *peerconn, NaughtyFilter &cm, String &url, bool is_icap, ICAPHeader *icap_head)
{
    String filedis = cm.tempfiledis;
    int fd = open(cm.tempfilename.toCharArray(), O_RDONLY);
    if (fd < 0) { // file access error
        syslog(LOG_ERR, "%sError reading file to send", thread_id.c_str());
#ifdef DGDEBUG
        std::cerr << thread_id << " -Error reading file to send:" << cm.tempfilename << std::endl;
#endif
        String fnf(o.language_list.getTranslation(1230));
        String head("HTTP/1.1 404 " + fnf + "\r\nContent-Type: text/html\r\n\r\n");
        String body("<HTML><HEAD><TITLE>" + fnf + "</TITLE></HEAD><BODY><H1>" + fnf + "</H1></BODY></HTML>\r\n");

        if (is_icap)
        {
            icap_head->out_res_header = head;
            icap_head->out_res_body = body;
            icap_head->out_res_hdr_flag = true;
            icap_head->out_res_body_flag = true;
            icap_head->respond(*peerconn);
        } else {
            peerconn->writeString(head.toCharArray());
            peerconn->writeString(body.toCharArray());
        }

        return 0;
    }

    off_t filesize = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    String head("HTTP/1.1 200 OK\r\nContent-Type: " + cm.tempfilemime + "\r\nContent-Length: " + String(filesize));
    if (filedis.length() == 0) {
        filedis = url.before("?");
        while (filedis.contains("/"))
            filedis = filedis.after("/");
    }
    head += "\r\nContent-disposition: attachment; filename=" + filedis;
    head += "\r\n\r\n";

    if (is_icap) {
        icap_head->out_res_header = head;
        icap_head->out_res_hdr_flag = true;
        icap_head->out_res_body_flag = true;
        icap_head->respond(*peerconn);
    } else {
        if (!peerconn->writeString(head.toCharArray())) {
            close(fd);
            return 0;
        }
    }

    // perform the actual sending
    off_t sent = 0;
    int rc;
    //char *buffer = new char[250000];
    char *buffer = new char[64000];
    while (sent < filesize) {
        rc = readEINTR(fd, buffer, 64000);
#ifdef DGDEBUG
        std::cerr << thread_id << " -reading send file rc:" << rc << std::endl;
#endif
        if (rc < 0) {
#ifdef DGDEBUG
            std::cerr << thread_id << " -error reading send file so throwing exception" << std::endl;
#endif
            delete[] buffer;
//            throw std::exception();
            cleanThrow("error reading send file", *peerconn);
        }
        if (rc == 0) {
#ifdef DGDEBUG
            std::cerr << thread_id << " -got zero bytes reading send file" << std::endl;
#endif
            break; // should never happen
        }
        if (is_icap) {
            if (!peerconn->writeChunk(buffer,rc,100000)) {
                delete[] buffer;
                cleanThrow("Error sending file to client", *peerconn);
            }
        } else {
            // as it's cached to disk the buffer must be reasonably big
            if (!peerconn->writeToSocket(buffer, rc, 0,100000)) {
                delete[] buffer;
                cleanThrow("Error sending file to client", *peerconn);
                // throw std::exception();
            }
        }
        sent += rc;
#ifdef DGDEBUG
        std::cerr << thread_id << " -total sent from temp:" << sent << std::endl;
#endif
    }
    if (is_icap) {
        String n;
        peerconn->writeChunkTrailer(n);
    }
    delete[] buffer;
    close(fd);
    return sent;
}

int ConnectionHandler::connectUpstream(Socket &sock, NaughtyFilter &cm, int port = 0)   // connects to to proxy or directly
{
 if(port == 0)
     port = cm.request_header->port;

    cm.upfailure = false;
    if (cm.isdirect) {
        String des_ip;
        if (cm.isiphost) {
            des_ip = cm.urldomain;
            sock.setTimeout(o.proxy_timeout);
            std::cerr << "Connecting to IPHost " << des_ip << " port " << port << std::endl;
            int rc = sock.connect(des_ip,port);
            if (rc < 0) {
                cm.message_no = 203;
                cm.upfailure = true;
            }
            return rc;
        } else {
            //dns lookup
            struct addrinfo hints, *infoptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = 0;
            hints.ai_protocol = 0;
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;
            int rc = getaddrinfo(cm.connect_site.toCharArray(), NULL, &hints, &infoptr);
            if (rc )  // problem
            {
#ifdef DGDEBUG
                std::cerr << thread_id << "connectUpstream: getaddrinfo returned " << rc << " for " << cm.connect_site << " " << gai_strerror(rc) << std::endl;
#endif
                switch (rc) {
                    case EAI_NONAME:
                        cm.message_no = 207;
                        break;
#ifdef EAI_NODATA
                    case EAI_NODATA:
                        cm.message_no = 208;
                        break;
#endif
                    case EAI_AGAIN:
                        cm.message_no = 209;
                        break;
                    case EAI_FAIL:
                        cm.message_no = 210;
                        break;
                     default:
                         cm.message_no = 210;  //TODO this shoudl heave it's own message??
                        break;
                }
                cm.upfailure = true;
                sock.close();
                return -1;
            }
            char t[256];
            struct addrinfo *p;
            for (p = infoptr; p != NULL; p = p->ai_next)
            {
                getnameinfo(p->ai_addr, p->ai_addrlen, t, sizeof(t), NULL, 0, NI_NUMERICHOST);
#ifdef DGDEBUG
                std::cerr << thread_id << "Connecting to IP " << t << " port " << port << std::endl;
#endif
                int rc = sock.connect(t,port);
                if (rc == 0){
                    freeaddrinfo(infoptr);
#ifdef DGDEBUG
                        std::cerr << thread_id << "Got connection upfailure is " << cm.upfailure << std::endl;
#endif
                        return 0;
                    }
                }
                freeaddrinfo(infoptr);
                cm.message_no = 203;
                cm.upfailure = true;
                return -1;
            }
        } else {  //is via proxy
            sock.setTimeout(1000);   //TODO - add loop and message numbers on error
            int rc = sock.connect(o.proxy_ip, o.proxy_port);
            if (rc < 0)
            {
                cm.upfailure = true;
                if (sock.isTimedout())
                    cm.message_no = 201;
                else
                    cm.message_no = 202;
            }
        return rc;
        }
    }

    // pass data between proxy and client, filtering as we go.
    // this is the only public function of ConnectionHandler
    int ConnectionHandler::handlePeer(Socket &peerconn, String &ip, stat_rec* &dystat, unsigned int lc_type)
    {
        persistent_authed = false;
        is_real_user = false;
        int rc = 0;
    //#ifdef DGDEBUG
        // for debug info only - TCP peer port
        //thread_id = peerconn.getPeerSourcePort();
    //#endif
        Socket proxysock;    // also used for direct connection

    switch (lc_type) {
        case  CT_PROXY:
            rc = handleConnection(peerconn, ip, false, proxysock, dystat);
            break;

    #ifdef __SSLMITM
        case  CT_THTTPS:
            rc = handleTHTTPSConnection(peerconn, ip, proxysock, dystat);
            break;
    #endif

        case  CT_ICAP:
            rc = handleICAPConnection(peerconn, ip, proxysock, dystat);
            break;

    }
        //if ( ldl->reload_id != load_id)
   //     rc = -1;
    return rc;
}

int ConnectionHandler::handleConnection(Socket &peerconn, String &ip, bool ismitm, Socket &proxysock,
                                        stat_rec *&dystat) {
    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    //peerconn.setTimeout(o.proxy_timeout);
    peerconn.setTimeout(o.pcon_timeout);

    // ldl = o.currentLists();

    HTTPHeader docheader(__HEADER_RESPONSE); // to hold the returned page header from proxy
    HTTPHeader header(__HEADER_REQUEST); // to hold the incoming client request headeri(ldl)

    // set a timeout as we don't want blocking 4 eva
    // this also sets how long a peerconn will wait for other requests
    header.setTimeout(o.pcon_timeout);
    docheader.setTimeout(o.exchange_timeout);


    //int bypasstimestamp = 0;


    // Content scanning plugins to use for request (POST) & response data
    std::deque<CSPlugin *> requestscanners;
    std::deque<CSPlugin *> responsescanners;

    std::string clientip(ip.toCharArray()); // hold the clients ip
    docheader.setClientIP(ip);

    if (clienthost) delete clienthost;

    clienthost = NULL; // and the hostname, if available
    matchedip = false;

    // clear list of parameters extracted from URL
    urlparams.clear();

    // clear out info about POST data
    postparts.clear();

#ifdef DGDEBUG // debug stuff surprisingly enough
    std::cerr << thread_id << " -got peer connection" << std::endl;
    std::cerr << thread_id << clientip << std::endl;
#endif

    try {
        int rc;

#ifdef DGDEBUG
        int pcount = 0;
#endif

        // assume all requests over the one persistent connection are from
        // the same user. means we only need to query the auth plugin until
        // we get credentials, then assume they are valid for all reqs. on
        // the persistent connection.
        std::string oldclientuser;
        std::string room;

        int oldfg = 0;
        bool authed = false;
        bool isbanneduser = false;
        bool isscanbypass = false;
        bool isbypass = false;
        bool isvirusbypass = false;
        //int bypasstimestamp = 0;
        bool iscookiebypass = false;

        AuthPlugin *auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistOutgoing = true;
        bool persistPeer = true;
        bool persistProxy = true;

        bool firsttime = true;
        if (!header.in(&peerconn, true)) {     // get header from client, allowing persistency
            if (o.logconerror) {
                    if (peerconn.getFD() > -1) {

                        int err = peerconn.getErrno();
                        int pport = peerconn.getPeerSourcePort();
                        std::string peerIP = peerconn.getPeerIP();

                        syslog(LOG_INFO, "%d No header recd from client at %s - errno: %d", pport, peerIP.c_str(), err);
#ifdef DGDEBUG
                        std::cerr << "pport" << " No header recd from client - errno: " << err << std::endl;
#endif
                    } else {
                        syslog(LOG_INFO, "Client connection closed early - no request header received");
                    }
            }
            firsttime = false;
            persistPeer = false;
        } else {
            ++dystat->reqs;
        }
        //
        // End of set-up section
        //
        // Start of main loop
        //

        // maintain a persistent connection
        while ((firsttime || persistPeer) && !ttg)
            //    while ((firsttime || persistPeer) && !reloadconfig)
        {
#ifdef DGDEBUG
            std::cerr << " firsttime =" << firsttime << "ismitm =" << ismitm << " clientuser =" << clientuser << " group = " << filtergroup << std::endl;
#endif
            ldl = o.currentLists();
            NaughtyFilter checkme(header, docheader);
            DataBuffer docbody;
            docbody.setTimeout(o.exchange_timeout);
            FDTunnel fdt;

            if (firsttime) {
                // reset flags & objects next time round the loop
                firsttime = false;
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;

                // quick trick for the very first connection :-)
                if (!ismitm)
                    persistProxy = false;
            } else {
// another round...
#ifdef DGDEBUG
                std::cerr << thread_id << " -persisting (count " << ++pcount << ")" << std::endl;
//                syslog(LOG_ERR, "Served %d requests on this connection so far - ismitm=%d", pcount, ismitm);
                std::cerr << thread_id << " - " << clientip << std::endl;
#endif
                header.reset();
                if (!header.in(&peerconn, true)) {
#ifdef DGDEBUG
                    std::cerr << thread_id << " -Persistent connection closed" << std::endl;
#endif
                    break;
                }
                ++dystat->reqs;

                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;

                checkme.bypasstimestamp = 0;

                authed = false;
                isbanneduser = false;
// Bypass
                isbypass = false;
                isscanbypass = false;
                isvirusbypass = false;

                requestscanners.clear();
                responsescanners.clear();

                matchedip = false;
                urlparams.clear();
                postparts.clear();
                checkme.mimetype = "-";
                //exceptionreason = "";
                //exceptioncat = "";
                room = "";    // CHECK THIS - surely room is persistant?????

                // reset docheader & docbody
                // headers *should* take care of themselves on the next in()
                // actually not entirely true for docheader - we may read
                // certain properties of it (in denyAccess) before we've
                // actually performed the next in(), so make sure we do a full
                // reset now.
                docheader.reset();
                docbody.reset();
                peerconn.resetChunk();
                proxysock.resetChunk();

            }
//
            // do this normalisation etc just the once at the start.
            checkme.setURL(ismitm);

            //If proxy connction is not persistent..// do this later after checking if direct or via proxy

#ifdef DGDEBUG
            std::cerr << thread_id << getpid() << "Start URL " << checkme.url.c_str() << "is_ssl=" << checkme.is_ssl << "ismitm=" << ismitm << std::endl;
#endif

            // checks for bad URLs to prevent security holes/domain obfuscation.
            if (header.malformedURL(checkme.url)) {
                // The requested URL is malformed.
                writeback_error(checkme, peerconn, 200, 0, "400 Bad Request");
                proxysock.close(); // close connection to proxy
                break;
            }

            // TODO this needs moving is proxy operation is still to be tested
            if (checkme.urldomain == "internal.test.e2guardian.org") {
                peerconn.writeString(
                        "HTTP/1.1 200 \nContent-Type: text/html\n\n<HTML><HEAD><TITLE>e2guardian internal test</TITLE></HEAD><BODY><H1>e2guardian internal test OK</H1> ");
                peerconn.writeString("</BODY></HTML>\n");
                proxysock.close(); // close connection to proxy
                break;
            }

            // do total block list checking here - now done in pre-auth story
#ifdef NOTDEF
            if (o.use_total_block_list && o.inTotalBlockList(checkme.urld)) {
                if (checkme.isconnect) {
                    writeback_error(checkme, peerconn, 0, 0, "404 Banned Site");
                } else { // write blank graphic
                    peerconn.writeString("HTTP/1.1 200 OK\n");
                    o.banned_image.display(&peerconn);
                }
                proxysock.close(); // close connection to proxy
                break;
            }
#endif

            // don't let the client connection persist if the client doesn't want it to.
            persistOutgoing = header.isPersistent();
            //
            //
            // Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            overide_persist = false;
            if (!persistent_authed) {
                bool only_ip_auth;
                if (header.isProxyRequest) {
                    filtergroup = o.default_fg;
                    only_ip_auth = false;
                }
                else
                {
                    filtergroup = o.default_trans_fg;
                    only_ip_auth = true;
                }
#ifdef DGDEBUG
                std::cerr << thread_id << "isProxyRequest is " << header.isProxyRequest << " only_ip_auth is " << only_ip_auth << std::endl;
#endif
                if (!doAuth(authed, filtergroup, auth_plugin, peerconn, proxysock, header,only_ip_auth))
                    break;
                //checkme.filtergroup = filtergroup;
            } else {
#ifdef DGDEBUG
                std::cerr << thread_id << " -Already got credentials for this connection - not querying auth plugins" << std::endl;
#endif
                authed = true;
            }
            checkme.filtergroup = filtergroup;

#ifdef DGDEBUG
            std::cerr << thread_id << " -username: " << clientuser << std::endl;
            std::cerr << thread_id << " -filtergroup: " << filtergroup << std::endl;
#endif
//
//
// End of Authentication Checking
//
//

#ifdef __SSLMITM
            //			Set if candidate for MITM
            //			(Exceptions will not go MITM)
            checkme.ismitmcandidate = checkme.isconnect && ldl->fg[filtergroup]->ssl_mitm && (header.port == 443);
#endif

            //
            //
            // Now check if user or machine is banned and room-based checking
            //
            //

            // is this user banned?
            isbanneduser = false;
            if (o.use_xforwardedfor) {
                bool use_xforwardedfor;
                if (o.xforwardedfor_filter_ip.size() > 0) {
                    use_xforwardedfor = false;
                    for (unsigned int i = 0; i < o.xforwardedfor_filter_ip.size(); i++) {
                        if (strcmp(clientip.c_str(), o.xforwardedfor_filter_ip[i].c_str()) == 0) {
                            use_xforwardedfor = true;
                            break;
                        }
                    }
                } else {
                    use_xforwardedfor = true;
                }
                if (use_xforwardedfor == 1) {
                    std::string xforwardip(header.getXForwardedForIP());
                    if (xforwardip.length() > 6) {
                        clientip = xforwardip;
                    }
#ifdef DGDEBUG
                    std::cerr << thread_id << " -using x-forwardedfor:" << clientip << std::endl;
#endif
                }
            }
            checkme.clientip = clientip;

            // Look up reverse DNS name of client if needed
            if (o.reverse_client_ip_lookups) {
                std::unique_ptr<std::deque<String> > hostnames;
                hostnames.reset(ipToHostname(clientip.c_str()));
                checkme.clienthost = std::string(hostnames->front().toCharArray());
            }

            //CALL SB pre-authcheck
            ldl->StoryA.runFunctEntry(ENT_STORYA_PRE_AUTH, checkme);
#ifdef DGDEBUG
            std::cerr << "After StoryA pre-authcheck" << checkme.isexception << " mess_no "
                      << checkme.message_no << std::endl;
#endif
            checkme.isItNaughty = checkme.isBlocked;
            // is this machine banned?
            //bool isbannedip = ldl->inBannedIPList(&clientip, clienthost);
            bool isbannedip = checkme.isBlocked;
            bool part_banned;
            if (isbannedip) {
                // matchedip = clienthost == NULL;
            } else {
                if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
                                checkme.urld)) {
#ifdef DGDEBUG
                    std::cerr << " isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << checkme.isexception << std::endl;
#endif
                    if (isbannedip) {
                        //       matchedip = clienthost == NULL;
                        checkme.isBlocked = checkme.isItNaughty = true;
                    }
                    if (checkme.isexception) {
                        // do reason codes etc
                        checkme.exceptionreason = o.language_list.getTranslation(630);
                        checkme.exceptionreason.append(room);
                        checkme.exceptionreason.append(o.language_list.getTranslation(631));
                        checkme.message_no = 632;
                    }
                }
            }


#ifdef ENABLE_ORIG_IP
            // if working in transparent mode and grabbing of original IP addresses is
            // enabled, does the original IP address match one of those that the host
            // we are going to resolves to?
            // Resolves http://www.kb.cert.org/vuls/id/435052
            if (o.get_orig_ip) {
                // XXX This will currently only work on Linux/Netfilter.
                sockaddr_in origaddr;
                socklen_t origaddrlen(sizeof(sockaddr_in));
                // Note: we assume that for non-redirected connections, this getsockopt call will
                // return the proxy server's IP, and not -1.  Hence, comparing the result with
                // the return value of Socket::getLocalIP() should tell us that the client didn't
                // connect transparently, and we can assume they aren't vulnerable.
                if (getsockopt(peerconn.getFD(), SOL_IP, SO_ORIGINAL_DST, &origaddr, &origaddrlen) < 0) {
                    syslog(LOG_ERR, "Failed to get client's original destination IP: %s", strerror(errno));
                    break;
                }

                std::string orig_dest_ip(inet_ntoa(origaddr.sin_addr));
                if (orig_dest_ip == peerconn.getLocalIP()) {
// The destination IP before redirection is the same as the IP the
// client has actually been connected to - they aren't connecting transparently.
#ifdef DGDEBUG
                    std::cerr << thread_id << " -SO_ORIGINAL_DST and getLocalIP are equal; client not connected transparently" << std::endl;
#endif
                } else {
                    // Look up domain from request URL, and check orig IP against resolved IPs
                    addrinfo hints;
                    memset(&hints, 0, sizeof(hints));
                    hints.ai_family = AF_INET;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    addrinfo *results;
                    int result = getaddrinfo(checkme.urldomain.c_str(), NULL, &hints, &results);
                    if (result) {
                        freeaddrinfo(results);
                        syslog(LOG_ERR, "Cannot resolve hostname for host header checks: %s", gai_strerror(errno));
                        break;
                    }
                    addrinfo *current = results;
                    bool matched = false;
                    while (current != NULL) {
                        if (orig_dest_ip == inet_ntoa(((sockaddr_in *)(current->ai_addr))->sin_addr)) {
#ifdef DGDEBUG
                            std::cerr << thread_id << checkme.urldomain << " matched to original destination of " << orig_dest_ip << std::endl;
#endif
                            matched = true;
                            break;
                        }
                        current = current->ai_next;
                    }
                    freeaddrinfo(results);
                    if (!matched) {
// Host header/URL said one thing, but the original destination IP said another.
// This is exactly the vulnerability we want to prevent.
#ifdef DGDEBUG
                        std::cerr << thread_id << checkme.urldomain << " DID NOT MATCH original destination of " << orig_dest_ip << std::endl;
#endif
                        syslog(LOG_ERR, "Destination host of %s did not match the original destination IP of %s", checkme.urldomain.c_str(), orig_dest_ip.c_str());
                            writeback_error(checkme,peercon,200,0,"400 Bad Request");
                        break;
                    }
                }
            }
#endif
            //
            // Start of by pass
            //
            if(checkByPass(checkme,ldl, header, proxysock, peerconn, clientip)
                    && sendScanFile(peerconn,checkme)) {
                persistProxy = false;
                break;
            }

            //
            // End by pass
            //

            // virus checking candidate?
            // checkme.noviruscheck defaults to true
            if (!(checkme.isconnect || checkme.ishead)    //  can't scan connect or head
                && !(checkme.isBlocked)  // or already blocked
                && (o.csplugins.size() > 0)            //  and we have scan plugins
                && !ldl->fg[filtergroup]->disable_content_scan    // and is not disabled
                && !(checkme.isexception && !ldl->fg[filtergroup]->content_scan_exceptions)
                            // and not exception unless scan exceptions enabled
                    )
                checkme.noviruscheck = false;   // note this may be reset by Storyboard to enable exceptions

            char *retchar;

            //
            // Start of Storyboard checking
            //
//            if (!(checkme.isBlocked || checkme.isbypass))
            if (!checkme.isBlocked) {
// Main checking is now done in Storyboard function(s)
                //   String funct = "checkrequest";
                //   ldl->fg[filtergroup]->StoryB.runFunct(funct, checkme);
                ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_PROXY_REQUEST, checkme);
#ifdef DGDEBUG
                std::cerr << thread_id << "After StoryB checkrequest isexception " << checkme.isexception << " gomitm "
                          << checkme.gomitm << " mess_no "
                          << checkme.message_no << std::endl;
#endif
                checkme.isItNaughty = checkme.isBlocked;
                if (checkme.isdirect) header.setDirect();
            }

            if (checkme.isbypass && !(checkme.isexception || checkme.iscookiebypass || checkme.isvirusbypass)) {
#ifdef DGDEBUG
                std::cout << thread_id << "Setting GBYPASS cookie; bypasstimestamp = " << checkme.bypasstimestamp << __func__ << std::endl;
#endif
                String ud(checkme.urldomain);
                if (ud.startsWith("www.")) {
                    ud = ud.after("www.");
                }
                // redirect user to URL with GBYPASS parameter no longer appended
                String outhead = "HTTP/1.1 302 Redirect\r\n";
                outhead += "Set-Cookie: GBYPASS=";
                outhead += hashedCookie(&ud, ldl->fg[filtergroup]->cookie_magic.c_str(),&clientip,
                                        checkme.bypasstimestamp).toCharArray();
                outhead += "; path=/; domain=.";
                outhead += ud;
                outhead += "\r\n";
                outhead += "Location: ";
                outhead += header.getUrl(true);
                outhead += "\r\n";
                outhead += "\r\n";
                peerconn.writeString(outhead.c_str());
                return 0;
            }


            //check for redirect
            // URL regexp search and edirect
            if (checkme.urlredirect) {
                checkme.url = header.redirecturl();
                proxysock.close();
                String writestring("HTTP/1.1 302 Redirect\nLocation: ");
                writestring += checkme.url;
                writestring += "\n\n";
                peerconn.writeString(writestring.toCharArray());
                break;
            }

            //if  is a search - content check search terms
            if (checkme.isSearch)
                check_search_terms(checkme);  // will set isItNaughty if needed


            // TODO V5 call POST scanning code New NaughtyFilter function????

            // don't run willScanRequest if content scanning is disabled, or on exceptions if contentscanexceptions is off,
            // or on SSL (CONNECT) requests, or on HEAD requests, or if in AV bypass mode

            //if not naughty now send upstream and get response
            if (checkme.isItNaughty) {
                if (checkme.isconnect && ldl->fg[filtergroup]->ssl_mitm) {
                    checkme.gomitm = true;   // so that we can deliver a status message to user over half MITM
                    if (checkme.isdirect) {  // send connection estabilished to client
                        std::string msg = "HTTP/1.1 200 Connection established\r\n\r\n";
                        if (!peerconn.writeString(msg.c_str()))
                            cleanThrow("Unable to send to client 859", peerconn);
                    }
                }
            } else {
                if (!persistProxy) // open upstream connection
                {
                    if (connectUpstream(proxysock, checkme) < 0) {
                                        if (checkme.isconnect && ldl->fg[filtergroup]->ssl_mitm && checkme.upfailure)
                                           checkme.gomitm = true;   // so that we can deliver a status message to user over half MITM
                        // give error - depending on answer
                        // timeout -etc
                    }
                }
                if (!checkme.upfailure) {
                    if (!proxysock.breadyForOutput(o.proxy_timeout))
                        cleanThrow("Unable to write upstream", peerconn, proxysock);
#ifdef DGDEBUG
                    std::cerr << thread_id << "  got past line 727 rfo " << std::endl;
#endif
                }
                if (checkme.isdirect && checkme.isconnect) {  // send connection estabilished to client
                    std::string msg = "HTTP/1.1 200 Connection established\r\n\r\n";
                    if (!peerconn.writeString(msg.c_str()))
                        cleanThrow("Unable to send to client 859", peerconn);
                } else if (!checkme.upfailure)  // in all other cases send header upstream and get response
                {
                    if (!(header.out(&peerconn, &proxysock, __DGHEADER_SENDALL, true) // send proxy the request
                          && (docheader.in(&proxysock, persistOutgoing)))) {
                        if (proxysock.isTimedout()) {
                            writeback_error(checkme, peerconn, 203, 204, "504 Gateway Time-out");
                        } else {
                            writeback_error(checkme, peerconn, 205, 206, "502 Gateway Error");
                        }
                        break;
                    }
                    persistProxy = docheader.isPersistent();
                    persistPeer = persistOutgoing && docheader.wasPersistent();
#ifdef DGDEBUG
                    std::cerr << thread_id << " -persistPeer: " << persistPeer << std::endl;
#endif

                    //check response code
                    if ((!checkme.isItNaughty) && (!checkme.upfailure)) {
                        int rcode = docheader.returnCode();
                        if (checkme.isconnect &&
                            (rcode != 200))  // some sort of problem or needs proxy auth - pass back to client
                        {
                            checkme.ismitmcandidate = false;  // only applies to connect
                            checkme.tunnel_rest = true;
                            checkme.tunnel_2way = false;
                        } else if (rcode == 407) {   // proxy auth required
                            // tunnel thru - no content
                            checkme.tunnel_rest = true;
                        }

                        if(docheader.contentLength() == 0)   // no content
                            checkme.tunnel_rest = true;
                    }
                }

            if(checkme.isconnect && checkme.isGrey) {  // allow legacy SSL behavour when mitm not enabled
                checkme.tunnel_2way = true;
                checkme.tunnel_rest = false;
            }
            }
            if (checkme.isexception && !checkme.upfailure)
            {
                if (checkme.isconnect) {
                    checkme.tunnel_2way = true;
                    checkme.tunnel_rest = false;
                } else {
                    if(!checkme.noviruscheck && !ldl->fg[filtergroup]->content_scan_exceptions)
                        checkme.noviruscheck = true;
                    if(checkme.noviruscheck) {
                        checkme.tunnel_2way = false;
                        checkme.tunnel_rest = true;
                    }
                }
            }

#ifdef __SSLMITM
            //if ismitm - GO MITM
            // check ssl_grey is covered in storyboard
            if (checkme.isconnect && checkme.gomitm)
            {
                std::cerr << "Going MITM ...." << std::endl;
                if(!ldl->fg[filtergroup]->mitm_check_cert)
                    checkme.nocheckcert = true;
                goMITM(checkme, proxysock, peerconn, persistProxy, authed, persistent_authed, ip, dystat, clientip,checkme.isdirect);
                persistPeer = false;
                persistProxy = false;
                if (!checkme.isItNaughty) // surely we should just break here whatever? - No we need to log error
                    break;
            }
#endif

            //CALL SB checkresponse
            if ((!checkme.isItNaughty) && (!checkme.upfailure) && (!checkme.isconnect)) {
                ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_PROXY_RESPONSE, checkme);
#ifdef DGDEBUG
                std::cerr << thread_id << "After StoryB checkresponse" << checkme.isexception << " mess_no "
                          << checkme.message_no << std::endl;
#endif
                checkme.isItNaughty = checkme.isBlocked;

                if (checkme.ishead || (docheader.contentLength() == 0 && !docheader.chunked))
                    checkme.tunnel_rest = true;

                if(checkme.isexception  && !ldl->fg[filtergroup]->content_scan_exceptions) {
                    checkme.tunnel_rest = true;
                    checkme.noviruscheck = true;
                }

                if(!checkme.noviruscheck)
                {
                    for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i) {
                        int csrc = ((CSPlugin *)(*i))->willScanRequest(header.getUrl(), clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(), false, false, checkme.isexception, checkme.isbypass);
                        if (csrc > 0)
                            responsescanners.push_back((CSPlugin *)(*i));
                        else if (csrc < 0)
                            syslog(LOG_ERR, "%swillScanRequest returned error: %d", thread_id.c_str(), csrc);
                    }
#ifdef DGDEBUG
                std::cerr << thread_id << " -Content scanners interested in response data: " << responsescanners.size() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                }

                //- if grey content check
                // can't do content filtering on HEAD or redirections (no content)
                // actually, redirections CAN have content
                if ((checkme.isGrey || !checkme.noviruscheck) && !checkme.tunnel_rest) {
                    check_content(checkme, docbody, proxysock, peerconn, responsescanners);
                }
            }

            //send response header to client
            if ((!checkme.isItNaughty) && (!checkme.upfailure) && !(checkme.isconnect && checkme.isdirect)) {
                if (!docheader.out(NULL, &peerconn, __DGHEADER_SENDALL, false))
                    cleanThrow("Unable to send return header to client", peerconn);

                if ((!checkme.isItNaughty) && checkme.waschecked) {
                    if (!docbody.out(&peerconn))
                        checkme.pausedtoobig = false;
                    if (checkme.pausedtoobig)
                        checkme.tunnel_rest = true;
                }
            }


            //if not grey tunnel response
            if (!checkme.isItNaughty) {
                if (checkme.tunnel_rest) {
                    bool chunked = docheader.transferEncoding().contains("chunked");
#ifdef DGDEBUG
                    std::cerr << thread_id << " -Tunnelling to client" << std::endl;
                    std::cerr << thread_id << " - Content-Length:" << docheader.contentLength() << "cm.docsize:" << checkme.docsize << std::endl;
#endif

                    if (!fdt.tunnel(proxysock, peerconn, checkme.isconnect, docheader.contentLength() - checkme.docsize,
                                    true, chunked))
                        persistProxy = false;
                    checkme.docsize += fdt.throughput;
                } else if (checkme.tunnel_2way) {
                    if (!fdt.tunnel(proxysock, peerconn, true))
                        persistProxy = false;
                    checkme.docsize = fdt.throughput;
                }
            }


#ifdef DGDEBUG
            std::cerr << thread_id << " -Forwarding body to client : Upfailure is " << checkme.upfailure << std::endl;
#endif
            if (checkme.upfailure || checkme.isItNaughty) {
                if (denyAccess(&peerconn, &proxysock, &header, &docheader, &checkme.url, &checkme, &clientuser,
                               &clientip,
                               filtergroup, checkme.ispostblock, checkme.headersent, checkme.wasinfected,
                               checkme.scanerror))
                    persistPeer = false;
            }

            //Log
            if (!checkme.isourwebserver) { // don't log requests to the web server
                doLog(clientuser, clientip, checkme);
            }


            if (!persistProxy)
                proxysock.close(); // close connection to proxy

            if (persistPeer) {
                continue;
            }

            break;
        }
    } catch (std::exception &e) {
#ifdef DGDEBUG
        std::cerr << thread_id << " -connection handler caught an exception: " << e.what() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        if (o.logconerror)
            syslog(LOG_ERR, "%s-connection handler caught an exception %s", thread_id.c_str(), e.what());

        // close connection to proxy
        proxysock.close();
        return -1;
    }
    if (!ismitm)
        try {
#ifdef DGDEBUG
            std::cerr << thread_id << " -Attempting graceful connection close" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            //syslog(LOG_INFO, " -Attempting graceful connection close" );
            int fd = peerconn.getFD();
            if (fd > -1) {
                if (shutdown(fd, SHUT_WR) == 0) {
                    char buff[2];
                    peerconn.readFromSocket(buff, 2, 0, 5000);
                };
            };

            // close connection to the client
            peerconn.close();
            proxysock.close();
        } catch (std::exception &e) {
#ifdef DGDEBUG
            std::cerr << thread_id << " -connection handler caught an exception on connection closedown: " << e.what() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            // close connection to the client
            peerconn.close();
            proxysock.close();
        }

    return 0;
}



void ConnectionHandler::doLog(std::string &who, std::string &from,NaughtyFilter &cm) {
    String rtype = cm.request_header->requestType();
//    doLog(who, from, cm.logurl,  cm.request_header->port, cm.whatIsNaughtyLog, rtype,
//          cm.docsize, &cm.whatIsNaughtyCategories, cm.isItNaughty, cm.blocktype, cm.isexception, cm.is_text, &cm.thestart,
 //         false, (cm.wasrequested ? cm.response_header->returnCode() : 200), cm.mimetype, cm.wasinfected,
  //        cm.wasscanned, cm.naughtiness, cm.filtergroup, cm.request_header, cm.message_no, cm.contentmodified,
   //       cm.urlmodified, cm.headermodified,  cm.headeradded);
//}

// decide whether or not to perform logging, categorise the log entry, and write it.
//void ConnectionHandler::doLog(std::string &who, std::string &from, String &where, unsigned int &port,
    //std::string &what, String &how, off_t &size, std::string *cat, bool isnaughty, int naughtytype,
    //bool isexception, bool istext, struct timeval *thestart, bool cachehit,
    //int code, std::string &mimetype, bool wasinfected, bool wasscanned, int naughtiness, int filtergroup,
    ////HTTPHeader *reqheader, int message_no, bool contentmodified, bool urlmodified, bool headermodified, bool headeradded)
///
    String where = cm.logurl;
    unsigned int port = cm.request_header->port;
    std::string what = cm.whatIsNaughtyLog;
    String how = rtype;
    off_t size = cm.docsize;
    std::string *cat = &cm.whatIsNaughtyCategories;
    bool isnaughty = cm.isItNaughty;
    int naughtytype = cm.blocktype;
    bool isexception = cm.isexception;
    bool istext = cm.is_text;
    struct timeval *thestart = &cm.thestart;
    bool cachehit = false;
    int code = (cm.wasrequested ? cm.response_header->returnCode() : 200);
    std::string mimetype = cm.mimetype;
    bool wasinfected = cm.wasinfected;
    bool wasscanned = cm.wasscanned;
    int naughtiness = cm.naughtiness;
    int filtergroup = cm.filtergroup;
    HTTPHeader *reqheader = cm.request_header;
    int message_no = cm.message_no;
    bool contentmodified = cm.contentmodified;
    bool urlmodified = cm.urlmodified;
    bool headermodified = cm.headermodified;
    bool headeradded = cm.headeradded;

    // don't log if logging disabled entirely, or if it's an ad block and ad logging is disabled,
    // or if it's an exception and exception logging is disabled
    if (
        (o.ll == 0) || ((cat != NULL) && !o.log_ad_blocks && (strstr(cat->c_str(), "ADs") != NULL)) || ((o.log_exception_hits == 0) && isexception)) {
#ifdef DGDEBUG
        if (o.ll != 0) {
            if (isexception)
                std::cerr << thread_id << " -Not logging exceptions" << std::endl;
            else
                std::cerr << thread_id << " -Not logging 'ADs' blocks" << std::endl;
        }
#endif
        return;
    }

    std::string data, cr("\n");

    if ((isexception && (o.log_exception_hits == 2))
        || isnaughty || o.ll == 3 || (o.ll == 2 && istext)) {
        // put client hostname in log if enabled.
        // for banned & exception IP/hostname matches, we want to output exactly what was matched against,
        // be it hostname or IP - therefore only do lookups here when we don't already have a cached hostname,
        // and we don't have a straight IP match agaisnt the banned or exception IP lists.
        if (o.log_client_hostnames && (clienthost == NULL) && !matchedip && !cm.anon_log) {
#ifdef DGDEBUG
            std::cerr << "logclienthostnames enabled but reverseclientiplookups disabled; lookup forced." << std::endl;
#endif
            std::deque<String> *names = ipToHostname(from.c_str());
            if (names->size() > 0)
                clienthost = new std::string(names->front().toCharArray());
            delete names;
        }

        // Build up string describing POST data parts, if any
        std::ostringstream postdata;
        for (std::list<postinfo>::iterator i = postparts.begin(); i != postparts.end(); ++i) {
            // Replace characters which would break log format with underscores
            std::string::size_type loc = 0;
            while ((loc = i->filename.find_first_of(",;\t ", loc)) != std::string::npos)
                i->filename[loc] = '_';
            // Build up contents of log column
            postdata << i->mimetype << "," << i->filename << "," << i->size
                     << "," << i->blocked << "," << i->storedname << "," << i->bodyoffset << ";";
        }
        postdata << std::flush;

        // Formatting code moved into log_listener in FatController.cpp
        // Original patch by J. Gauthier

        // Item length limit put back to avoid log listener
        // overload with very long urls Philip Pearce Jan 2014
        if ((cat != NULL) && (cat->length() > o.max_logitem_length))
            cat->resize(o.max_logitem_length);
        if (what.length() > o.max_logitem_length)
            what.resize(o.max_logitem_length);
        if (where.length() > o.max_logitem_length)
            where.limitLength(o.max_logitem_length);
        if (o.dns_user_logging && !is_real_user) {
            String user;
            if (getdnstxt(from,user)) {
                who = who + ":" + user;
            };
            is_real_user = true;    // avoid looping on persistent connections
        };
        std::string l_who = who;
        std::string l_from = from;
        std::string l_clienthost;
        if(clienthost != NULL)
            std::string l_clienthost = *clienthost;

        if(cm.anon_log) {
            l_who = "";
            l_from = "0.0.0.0";
            l_clienthost = "";
        }

#ifdef DGDEBUG
        std::cerr << thread_id << " -Building raw log data string... ";
#endif

        data = String(isexception) + cr;
        data += (cat ? (*cat) + cr : cr);
        data += String(isnaughty) + cr;
        data += String(naughtytype) + cr;
        data += String(naughtiness) + cr;
        data += where + cr;
        data += what + cr;
        data += how + cr;
        data += l_who + cr;
        data += l_from + cr;
        data += String(port) + cr;
        data += String(wasscanned) + cr;
        data += String(wasinfected) + cr;
        data += String(contentmodified) + cr;
        data += String(urlmodified) + cr;
        data += String(headermodified) + cr;
        data += String(size) + cr;
        data += String(filtergroup) + cr;
        data += String(code) + cr;
        data += String(cachehit) + cr;
        data += String(mimetype) + cr;
        data += String((*thestart).tv_sec) + cr;
        data += String((*thestart).tv_usec) + cr;
        data += l_clienthost + cr ;
        if (o.log_user_agent)
            data += (reqheader ? reqheader->userAgent() + cr : cr);
        else
            data += cr;
        data += urlparams + cr;
        data += postdata.str().c_str() + cr;
        data += String(message_no) + cr;
        data += String(headeradded) + cr;

#ifdef DGDEBUG
        std::cerr << thread_id << " -...built" << std::endl;
#endif

        //delete newcat;
// push on log queue
        o.log_Q->push(data);
        // connect to dedicated logging proc
    }
}



// TODO - V5
#ifdef NOTDEF
// check if embeded url trusted referer
bool ConnectionHandler::embededRefererChecks(HTTPHeader *header, String *urld, String *url,
    int filtergroup)
{

    char *i;
    int j;
    String temp;
    temp = (*urld);
    temp.hexDecode();

    if (ldl->fg[filtergroup]->inRefererExceptionLists(header->getReferer())) {
        return true;
    }
#ifdef DGDEBUG
    std::cerr << thread_id << " -checking for embed url in " << temp << std::endl;
#endif

    if (ldl->fg[filtergroup]->inEmbededRefererLists(temp)) {

// look for referer URLs within URLs
#ifdef DGDEBUG
        std::cerr << thread_id << " -starting embeded referer deep analysis" << std::endl;
#endif
        String deepurl(temp.after("p://"));
        deepurl = header->decode(deepurl, true);
        while (deepurl.contains(":")) {
            deepurl = deepurl.after(":");
            while (deepurl.startsWith(":") || deepurl.startsWith("/")) {
                deepurl.lop();
            }

            if (ldl->fg[filtergroup]->inRefererExceptionLists(deepurl)) {
#ifdef DGDEBUG
                std::cerr << "deep site found in trusted referer list; " << std::endl;
#endif
                return true;
            }
        }
#ifdef DGDEBUG
        std::cerr << thread_id << " -done embdeded referer deep analysis" << std::endl;
#endif
    }
    return false;
}
#endif

// based on patch by Aecio F. Neto (afn@harvest.com.br) - Harvest Consultoria (http://www.harvest.com.br)
// show the relevant banned page/image/CGI based on report level setting, request type etc.
bool ConnectionHandler::genDenyAccess(Socket &peerconn, String &eheader, String &ebody, HTTPHeader *header, HTTPHeader *docheader,
    String *url, NaughtyFilter *checkme, std::string *clientuser, std::string *clientip, int filtergroup,
    bool ispostblock, int headersent, bool wasinfected, bool scanerror, bool forceshow)
{
    int reporting_level = ldl->fg[filtergroup]->reporting_level;
#ifdef DGDEBUG

    std::cerr << thread_id << " -reporting level is " << reporting_level << std::endl;

#endif
    if (checkme->whatIsNaughty == "" && checkme->message_no > 0) {
        checkme->whatIsNaughty = o.language_list.getTranslation(checkme->message_no);
    }
    if (checkme->whatIsNaughtyLog == "") {
        if (checkme->log_message_no > 0) {
            checkme->whatIsNaughtyLog = o.language_list.getTranslation(checkme->log_message_no);
        } else {
            checkme->whatIsNaughtyLog = checkme->whatIsNaughty;
        }
    }

    try { // writestring throws exception on error/timeout

        // flags to enable filter/infection / hash generation
        bool filterhash = false;
        bool virushash = false;
        // flag to enable internal generation of hashes (i.e. obey the "-1" setting; to allow the modes but disable hash generation)
        // (if disabled, just output '1' or '2' to show that the CGI should generate a filter/virus bypass hash;
        // otherwise, real hashes get put into substitution variables/appended to the ban CGI redirect URL)
        bool dohash = false;
        if (reporting_level > 0) {
            // generate a filter bypass hash
            if (!wasinfected && (checkme->isbypassallowed) && !ispostblock) {
#ifdef DGDEBUG
                std::cerr << thread_id << " -Enabling filter bypass hash generation" << std::endl;
#endif
                filterhash = true;
                if (ldl->fg[filtergroup]->bypass_mode > 0)
                    dohash = true;
            }
            // generate an infection bypass hash
            else if (wasinfected && checkme->isinfectionbypassallowed) {
                // only generate if scanerror (if option to only bypass scan errors is enabled)
                if ((*ldl->fg[filtergroup]).infection_bypass_errors_only ? scanerror : true) {
#ifdef DGDEBUG
                    std::cerr << thread_id << " -Enabling infection bypass hash generation" << std::endl;
#endif
                    virushash = true;
                    if (ldl->fg[filtergroup]->infection_bypass_mode > 0)
                        dohash = true;
                }
            }
        }

// the user is using the full whack of custom banned images and/or HTML templates
#ifdef __SSLMITM
 	if (reporting_level == 3 || (headersent > 0 && reporting_level > 0) || forceshow || (ldl->fg[filtergroup]->sslaccess_denied_address.length() && ((*header).requestType().startsWith("CONNECT"))))
#else
	if (reporting_level == 3 || (headersent > 0 && reporting_level > 0) || (ldl->fg[filtergroup]->sslaccess_denied_address.length() && ((*header).requestType().startsWith("CONNECT"))))
#endif
        {
            // if reporting_level = 1 or 2 and headersent then we can't
            // send a redirect so we have to display the template instead


#ifdef __SSLMITM
            if ((*header).requestType().startsWith("CONNECT") && !(peerconn).isSsl())
#else
            if ((*header).requestType().startsWith("CONNECT"))
#endif
                {
                // if it's a CONNECT then headersent can't be set
                // so we don't need to worry about it

                // if preemptive banning is not in place then a redirect
                // is not guaranteed to ban the site so we have to write
                // an access denied page.  Unfortunately IE does not
                // work with access denied pages on SSL more than a few
                // hundred bytes so we have to use a crap boring one
                // instead.  Nothing can be done about it - blame
                // mickysoft.
                //
                // FredB 2013
                // Wrong Microsoft is right, no data will be accepted without hand shake
                // This is a Man in the middle problem with Firefox and IE (can't rewrite a ssl page)
                // 307 redirection Fix the problem for Firefox - only ? -
                // TODO: I guess the right thing to do should be a - SSL - DENIED Webpage 307 redirect and direct"

                if (ldl->fg[filtergroup]->sslaccess_denied_address.length() != 0) {
                    // grab either the full category list or the thresholded list
                    std::string cats;
                    cats = checkme->usedisplaycats ? checkme->whatIsNaughtyDisplayCategories : checkme->whatIsNaughtyCategories;
                    String hashed;
                    // generate valid hash locally if enabled
                    if (dohash) {
                        hashed = hashedURL(url, filtergroup, clientip, virushash);
                    }
                    // otherwise, just generate flags showing what to generate
                    else if (filterhash) {
                        hashed = "1";
                    } else if (virushash) {
                        hashed = "2";
                    }

                    eheader = "HTTP/1.1 307 Temporary Redirect\r\n";
                    eheader += "Location: ";
                    eheader += ldl->fg[filtergroup]->sslaccess_denied_address; // banned site for ssl
                    if (ldl->fg[filtergroup]->non_standard_delimiter) {
                        eheader += "?DENIEDURL==";
                        eheader += miniURLEncode((*url).toCharArray()).c_str();
                        eheader += "::IP==";
                        eheader += (*clientip).c_str();
                        eheader += "::USER==";
                        eheader += (*clientuser).c_str();
			eheader += "::FILTERGROUP==";
			eheader += ldl->fg[filtergroup]->name;
                        if (clienthost != NULL) {
                            eheader += "::HOST==";
                            eheader += clienthost->c_str();
                        }
                        eheader += "::CATEGORIES==";
                        eheader += miniURLEncode(cats.c_str()).c_str();
                        eheader += "::REASON==";
                    } else {
                        eheader += "?DENIEDURL=";
                        eheader += miniURLEncode((*url).toCharArray()).c_str();
                        eheader += "&IP=";
                        eheader += (*clientip).c_str();
                        eheader += "&USER=";
                        eheader += (*clientuser).c_str();
			eheader += "&FILTERGROUP=";
			eheader += ldl->fg[filtergroup]->name;
                        if (clienthost != NULL) {
                            eheader += "&HOST=";
                            eheader += clienthost->c_str();
                        }
                        eheader += "&CATEGORIES=";
                        eheader += miniURLEncode(cats.c_str()).c_str();
                        eheader += "&REASON=";
                    }

                    if (reporting_level == 1) {
                        eheader += miniURLEncode((*checkme).whatIsNaughty.c_str()).c_str();
                    } else {
                        eheader += miniURLEncode((*checkme).whatIsNaughtyLog.c_str()).c_str();
                    }
                    eheader += "\r\nContent-Length: 0";
                    eheader += "\r\nCache-control: no-cache";
                    eheader += "\r\nConnection: close\r\n\r\n";
                } else {
                    // Broken, sadly blank page for user
                    // See comment above HTTPS
                    eheader = "HTTP/1.1 403 ";
                    eheader += o.language_list.getTranslation(500); // banned site
                    eheader += "\r\nContent-Type: text/html\r\n";
                    ebody = "<HTML><HEAD><TITLE>e2guardian - ";
                    ebody += o.language_list.getTranslation(500); // banned site
                    ebody += "</TITLE></HEAD><BODY><H1>e2guardian - ";
                    ebody += o.language_list.getTranslation(500); // banned site
                    ebody += "</H1>";
                    ebody += (*url);
                    ebody += "</BODY></HTML>\r\n";
                    eheader += "Content-Length: ";
                    eheader += std::to_string(ebody.size());
                    eheader += "\r\n\r\n";
                }

            } else {
                // we're dealing with a non-SSL'ed request, and have the option of using the custom banned image/page directly
                bool replaceimage = false;
                bool replaceflash = false;
                if (o.use_custom_banned_image) {

                    // It would be much nicer to do a mime comparison
                    // and see if the type is image/* but the header
                    // never (almost) gets back from squid because
                    // it gets denied before then.
                    // This method is prone to over image replacement
                    // but will work most of the time.

                    String lurl((*url));
                    lurl.toLower();
                    if (lurl.endsWith(".gif") || lurl.endsWith(".jpg") || lurl.endsWith(".jpeg") || lurl.endsWith(".jpe")
                        || lurl.endsWith(".png") || lurl.endsWith(".bmp") || (*docheader).isContentType("image/",ldl->fg[filtergroup])) {
                        replaceimage = true;
                    }
                }

                if (o.use_custom_banned_flash) {
                    String lurl((*url));
                    lurl.toLower();
                    if (lurl.endsWith(".swf") || (*docheader).isContentType("application/x-shockwave-flash",ldl->fg[filtergroup])) {
                        replaceflash = true;
                    }
                }

                // if we're denying an image request, show the image; otherwise, show the HTML page.
                // (or advanced ad block page, or HTML page with bypass URLs)
                if (replaceimage) {
                    if (headersent == 0) {
                        eheader = "HTTP/1.1 200 OK\r\n";
                    }
                    o.banned_image.display_hb(eheader, ebody);
                } else if (replaceflash) {
                    if (headersent == 0) {
                        eheader = "HTTP/1.1 200 OK\r\n";
                    }
                    o.banned_flash.display_hb(eheader, ebody);
                } else {
                    // advanced ad blocking - if category contains ADs, wrap ad up in an "ad blocked" message,
                    // which provides a link to the original URL if you really want it. primarily
                    // for IFRAMEs, which will end up containing this link instead of the ad (standard non-IFRAMEd
                    // ad images still get image-replaced.)
                    if (strstr(checkme->whatIsNaughtyCategories.c_str(), "ADs") != NULL) {
                        eheader = "HTTP/1.1 200 \r\n";
                        eheader += o.language_list.getTranslation(1101); // advert blocked
                        eheader += "\r\nContent-Type: text/html\r\n";
                        ebody = "<HTML><HEAD><TITLE>E2guardian - ";
                        ebody += o.language_list.getTranslation(1101); // advert blocked
                        ebody += "</TITLE></HEAD><BODY><CENTER><FONT SIZE=\"-1\"><A HREF=\"";
                        ebody += (*url);
                        ebody += "\" TARGET=\"_BLANK\">";
                        ebody += o.language_list.getTranslation(1101); // advert blocked
                        ebody += "</A></FONT></CENTER></BODY></HTML>\r\n";
                        eheader += "Content-Length: ";
                        eheader += std::to_string(ebody.size());
                        eheader += "\r\n\r\n";
                    }

                    // Mod by Ernest W Lessenger Mon 2nd February 2004
                    // Other bypass code mostly written by Ernest also
                    // create temporary bypass URL to show on denied page
                    else {
                        String hashed;
                        // generate valid hash locally if enabled
                        if (dohash) {
                            hashed = hashedURL(url, filtergroup, clientip, virushash);
                        }
                        // otherwise, just generate flags showing what to generate
                        else if (filterhash) {
                            hashed = "HASH=1";
                        } else if (virushash) {
                            hashed = "HASH=2";
                        }

                        if (headersent == 0) {
                            eheader = "HTTP/1.1 200 \r\n";
                        }
                        if (headersent < 2) {
                            eheader += "Content-type: text/html\n\n";
                        }
                        // if the header has been sent then likely displaying the
                        // template will break the download, however as this is
                        // only going to be happening if the unsafe trickle
                        // buffer method is used and we want the download to be
                        // broken we don't mind too much
                        //String fullurl = header->getLogUrl(true);
                        String fullurl = checkme->logurl;
                        String localip = peerconn.getLocalIP();
                        ldl->fg[filtergroup]->getHTMLTemplate()->display_hb(ebody,
                            &fullurl, (*checkme).whatIsNaughty, (*checkme).whatIsNaughtyLog,
                            // grab either the full category list or the thresholded list
                            (checkme->usedisplaycats ? checkme->whatIsNaughtyDisplayCategories : checkme->whatIsNaughtyCategories),
                            clientuser, clientip, clienthost, filtergroup, ldl->fg[filtergroup]->name, hashed, localip);
                    }
                }
            }
        }

        // the user is using the CGI rather than the HTML template - so issue a redirect with parameters filled in on GET string
        else if (reporting_level > 0) {
            // grab either the full category list or the thresholded list
            std::string cats;
            cats = checkme->usedisplaycats ? checkme->whatIsNaughtyDisplayCategories : checkme->whatIsNaughtyCategories;

            String hashed;
            // generate valid hash locally if enabled
            if (dohash) {
                hashed = hashedURL(url, filtergroup, clientip, virushash);
            }
            // otherwise, just generate flags showing what to generate
            else if (filterhash) {
                hashed = "1";
            } else if (virushash) {
                hashed = "2";
            }

            if ((*checkme).whatIsNaughty.length() > 2048) {
                (*checkme).whatIsNaughty = String((*checkme).whatIsNaughty.c_str()).subString(0, 2048).toCharArray();
            }
            if ((*checkme).whatIsNaughtyLog.length() > 2048) {
                (*checkme).whatIsNaughtyLog = String((*checkme).whatIsNaughtyLog.c_str()).subString(0, 2048).toCharArray();
            }
            eheader = "HTTP/1.1 302 Redirect\r\n";
            eheader += "Location: ";
            eheader += ldl->fg[filtergroup]->access_denied_address;

            if (ldl->fg[filtergroup]->non_standard_delimiter) {
                eheader += "?DENIEDURL==";
                eheader += miniURLEncode((*url).toCharArray()).c_str();
                eheader += "::IP==";
                eheader += (*clientip).c_str();
                eheader += "::USER==";
                eheader += (*clientuser).c_str();
		eheader += "::FILTERGROUP==";
		eheader += ldl->fg[filtergroup]->name;
                if (clienthost != NULL) {
                    eheader += "::HOST==";
                    eheader += clienthost->c_str();
                }
                eheader += "::CATEGORIES==";
                eheader += miniURLEncode(cats.c_str()).c_str();
                if (virushash || filterhash) {
                    // output either a genuine hash, or just flags
                    if (dohash) {
                        eheader += "::";
                        eheader += hashed.before("=").toCharArray();
                        eheader += "==";
                        eheader += hashed.after("=").toCharArray();
                    } else {
                        eheader += "::HASH==";
                        eheader += hashed.toCharArray();
                    }
                }
                eheader += "::REASON==";
            } else {
                eheader += "?DENIEDURL=";
                eheader += miniURLEncode((*url).toCharArray()).c_str();
                eheader += "&IP=";
                eheader += (*clientip).c_str();
                eheader += "&USER=";
                eheader += (*clientuser).c_str();
		eheader += "&FILTERGROUP=";
		eheader += ldl->fg[filtergroup]->name;
                if (clienthost != NULL) {
                    eheader += "&HOST=";
                    eheader += clienthost->c_str();
                }
                eheader += "&CATEGORIES=";
                eheader += miniURLEncode(cats.c_str()).c_str();
                if (virushash || filterhash) {
                    // output either a genuine hash, or just flags
                    if (dohash) {
                        eheader += "&";
                        eheader += hashed.toCharArray();
                    } else {
                        eheader += "&HASH=";
                        eheader += hashed.toCharArray();
                    }
                }
                eheader += "&REASON=";
            }
            if (reporting_level == 1) {
                eheader += miniURLEncode((*checkme).whatIsNaughty.c_str()).c_str();
            } else {
                eheader += miniURLEncode((*checkme).whatIsNaughtyLog.c_str()).c_str();
            }
            eheader += "\r\n\r\n";
        }

        // the user is using the barebones banned page
        else if (reporting_level == 0) {
            eheader = "HTTP/1.1 200 OK\r\n";
            eheader += "Content-type: text/html\r\n";
            ebody = "<HTML><HEAD><TITLE>e2guardian - ";
            ebody += o.language_list.getTranslation(1); // access denied
            ebody += "</TITLE></HEAD><BODY><CENTER><H1>e2guardian - ";
            ebody += o.language_list.getTranslation(1); // access denied
            ebody += "</H1></CENTER></BODY></HTML>\r\n";
            eheader += "Content-Length: ";
            eheader += std::to_string(ebody.size());
            eheader += "\r\n\r\n";
        }

        // stealth mode
        else if (reporting_level == -1) {
            (*checkme).isItNaughty = false; // dont block
            return false;
        }
    } catch (std::exception &e) {
    }
return true;
}    // end of deny request loop

// show the relevant banned page/image/CGI based on report level setting, request type etc.
bool ConnectionHandler::denyAccess(Socket *peerconn, Socket *proxysock, HTTPHeader *header, HTTPHeader *docheader,
    String *url, NaughtyFilter *checkme, std::string *clientuser, std::string *clientip, int filtergroup,
    bool ispostblock, int headersent, bool wasinfected, bool scanerror, bool forceshow)
{
    String eheader, ebody;
    if (genDenyAccess(*peerconn,eheader, ebody, header, docheader, url, checkme, clientuser, clientip, filtergroup,
    ispostblock, headersent, wasinfected, scanerror, forceshow)) {
        peerconn->writeString(eheader.toCharArray());
        if(ebody.length() > 0)
            peerconn->writeString(ebody.toCharArray());
    };

    // we blocked the request, so flush the client connection & close the proxy connection.
    if ((*checkme).isItNaughty) {
            (*peerconn).breadyForOutput(o.proxy_timeout); //as best a flush as I can
        (*proxysock).close(); // close connection to proxy
        // we said no to the request, so return true, indicating exit the connhandler
        return true;
    }
    ldl.reset();
    return false;
}    // end of deny request loop

// do content scanning (AV filtering) and naughty filtering
void ConnectionHandler::contentFilter(HTTPHeader *docheader, HTTPHeader *header, DataBuffer *docbody,
    Socket *proxysock, Socket *peerconn, int *headersent, bool *pausedtoobig, off_t *docsize, NaughtyFilter *checkme,
    bool wasclean, int filtergroup, std::deque<CSPlugin *> &responsescanners,
    std::string *clientuser, std::string *clientip, bool *wasinfected, bool *wasscanned, bool isbypass,
    String &url, String &domain, bool *scanerror, bool &contentmodified, String *csmessage)
{
    int rc = 0;

    //proxysock->bcheckForInput(120000);
    bool compressed = docheader->isCompressed();
    if (compressed) {
#ifdef DGDEBUG
        std::cerr << thread_id << " -Decompressing as we go....." << std::endl;
#endif
        docbody->setDecompress(docheader->contentEncoding());
    }
#ifdef DGDEBUG
    std::cerr << thread_id << docheader->contentEncoding() << std::endl;
    std::cerr << thread_id << " -about to get body from proxy" << std::endl;
#endif
    (*pausedtoobig) = docbody->in(proxysock, peerconn, header, docheader, !responsescanners.empty(), headersent); // get body from proxy
// checkme: surely if pausedtoobig is true, we just want to break here?
// the content is larger than max_content_filecache_scan_size if it was downloaded for scanning,
// and larger than max_content_filter_size if not.
// in fact, why don't we check the content length (when it's not -1) before even triggering the download managers?
#ifdef DGDEBUG
    if ((*pausedtoobig)) {
        std::cerr << thread_id << " -got PARTIAL body " << std::endl;
    } else {
        std::cerr << thread_id << " -got body" << std::endl;
    }
#endif
    off_t dblen;
    bool isfile = false;
    if (docbody->tempfilesize > 0) {
        dblen = docbody->tempfilesize;
        isfile = true;
    } else {
        dblen = docbody->buffer_length;
    }
    // don't scan zero-length buffers (waste of AV resources, especially with external scanners (ICAP)).
    // these were encountered browsing opengroup.org, caused by a stats script. (PRA 21/09/2005)
    // if we wanted to honour a hypothetical min_content_scan_size, we'd do it here.
    if (((*docsize) = dblen) == 0) {
#ifdef DGDEBUG
        std::cerr << thread_id << " -Not scanning zero-length body" << std::endl;
#endif
        // it's not inconceivable that we received zlib or gzip encoded content
        // that is, after decompression, zero length. we need to cater for this.
        // seen on SW's internal MediaWiki.
        docbody->swapbacktocompressed();
        return;
    }

    if (!wasclean) { // was not clean or no urlcache

        // fixed to obey maxcontentramcachescansize
        if (!responsescanners.empty() && (isfile ? dblen <= o.max_content_filecache_scan_size : dblen <= o.max_content_ramcache_scan_size)) {
            int csrc = 0;
#ifdef DGDEBUG
            int k = 0;
#endif
            for (std::deque<CSPlugin *>::iterator i = responsescanners.begin(); i != responsescanners.end(); i++) {
                (*wasscanned) = true;
                if (isfile) {
#ifdef DGDEBUG
                    std::cerr << thread_id << " -Running scanFile" << std::endl;
#endif
                    csrc = (*i)->scanFile(header, docheader, clientuser->c_str(), ldl->fg[filtergroup], clientip->c_str(), docbody->tempfilepath.toCharArray(), checkme);
                    if ((csrc != DGCS_CLEAN) && (csrc != DGCS_WARNING)) {
                        unlink(docbody->tempfilepath.toCharArray());
                        // delete infected (or unscanned due to error) file straight away
                    }
                } else {
#ifdef DGDEBUG
                    std::cerr << thread_id << " -Running scanMemory" << std::endl;
#endif
                    csrc = (*i)->scanMemory(header, docheader, clientuser->c_str(), ldl->fg[filtergroup], clientip->c_str(), docbody->data, docbody->buffer_length, checkme);
                }
#ifdef DGDEBUG
                std::cerr << thread_id << " -AV scan " << k << " returned: " << csrc << std::endl;
#endif
                if (csrc == DGCS_WARNING) {
                    // Scanner returned a warning. File wasn't infected, but wasn't scanned properly, either.
                    (*wasscanned) = false;
                    (*scanerror) = false;
#ifdef DGDEBUG
                    std::cerr << thread_id << (*i)->getLastMessage() << std::endl;
#endif
                    (*csmessage) = (*i)->getLastMessage();
                } else if (csrc == DGCS_BLOCKED) {
                    (*wasscanned) = true;
                    (*scanerror) = false;
                    break;
                } else if (csrc == DGCS_INFECTED) {
                    (*wasinfected) = true;
                    (*scanerror) = false;
                    break;
                }
                //if its not clean / we errored then treat it as infected
                else if (csrc != DGCS_CLEAN) {
                    if (csrc < 0) {
                        syslog(LOG_ERR, "Unknown return code from content scanner: %d", csrc);
			if (ldl->fg[filtergroup]->disable_content_scan_error) {
				syslog(LOG_ERR, "disablecontentscanerror is on : bypass actived USER: %s URL: %s ", clientip->c_str(), url.c_str());
				(*wasscanned) = false;
                    		(*wasinfected) = false;
                                break;
			}
                    } else {
                        syslog(LOG_ERR, "scanFile/Memory returned error: %d", csrc);
                    }
                    //TODO: have proper error checking/reporting here?
                    //at the very least, integrate with the translation system.
                    //checkme->whatIsNaughty = "WARNING: Could not perform content scan!";
                    checkme->message_no = 1203;
                    checkme->whatIsNaughty = o.language_list.getTranslation(1203);
                    checkme->whatIsNaughtyLog = (*i)->getLastMessage().toCharArray();
                    //checkme->whatIsNaughtyCategories = "Content scanning";
                    checkme->whatIsNaughtyCategories = o.language_list.getTranslation(72);
                    checkme->isItNaughty = true;
                    checkme->isException = false;
                    (*scanerror) = true;
                    break;
                }
#ifdef DGDEBUG
                k++;
#endif
            }

#ifdef DGDEBUG
            std::cerr << thread_id << " -finished running AV" << std::endl;
//            rc = system("date");
#endif
        }
#ifdef DGDEBUG
        else if (!responsescanners.empty()) {
            std::cerr << thread_id << " -content length large so skipping content scanning (virus) filtering" << std::endl;
        }
//        rc = system("date");
#endif
        if (!checkme->isItNaughty && !checkme->isException && !isbypass && (dblen <= o.max_content_filter_size)
            && !docheader->authRequired() && (docheader->isContentType("text",ldl->fg[filtergroup]) || docheader->isContentType("-",ldl->fg[filtergroup]))) {
#ifdef DGDEBUG
            std::cerr << thread_id << " -Start content filtering: ";
#endif
            checkme->checkme(docbody->data, docbody->buffer_length, &url, &domain,
                ldl->fg[filtergroup], ldl->fg[filtergroup]->banned_phrase_list, ldl->fg[filtergroup]->naughtyness_limit);
#ifdef DGDEBUG
            std::cerr << thread_id << " -Done content filtering: ";
#endif
        }
#ifdef DGDEBUG
        else {
            std::cerr << thread_id << " -Skipping content filtering: ";
            if (dblen > o.max_content_filter_size)
                std::cerr << thread_id << " -Content too large";
            else if (checkme->isException)
                std::cerr << thread_id << " -Is flagged as an exception";
            else if (checkme->isItNaughty)
                std::cerr << thread_id << " -Is already flagged as naughty (content scanning)";
            else if (isbypass)
                std::cerr << thread_id << " -Is flagged as a bypass";
            else if (docheader->authRequired())
                std::cerr << thread_id << " -Is a set of auth required headers";
            else if (!docheader->isContentType("text",ldl->fg[filtergroup]))
                std::cerr << thread_id << " -Not text";
            std::cerr << thread_id << std::endl;
        }
#endif
    }

    // don't do phrase filtering or content replacement on exception/bypass accesses
    if (checkme->isException || isbypass) {
        // don't forget to swap back to compressed!
        docbody->swapbacktocompressed();
        return;
    }

    if ((dblen <= o.max_content_filter_size) && !checkme->isItNaughty && docheader->isContentType("text",ldl->fg[filtergroup])) {
        contentmodified = docbody->contentRegExp(ldl->fg[filtergroup]);
        // content modifying uses global variable
    }
#ifdef DGDEBUG
    else {
        std::cerr << thread_id << " -Skipping content modification: ";
        if (dblen > o.max_content_filter_size)
            std::cerr << thread_id << " -Content too large";
        else if (!docheader->isContentType("text",ldl->fg[filtergroup]))
            std::cerr << thread_id << " -Not text";
        else if (checkme->isItNaughty)
            std::cerr << thread_id << " -Already flagged as naughty";
        std::cerr << thread_id << std::endl;
    }
    //rc = system("date");
#endif

    if (contentmodified) { // this would not include infected/cured files
// if the content was modified then it must have fit in ram so no
// need to worry about swapped to disk stuff
#ifdef DGDEBUG
        std::cerr << thread_id << " -content modification made" << std::endl;
#endif
        if (compressed) {
            docheader->removeEncoding(docbody->buffer_length);
            // need to modify header to mark as not compressed
            // it also modifies Content-Length as well
        } else {
            docheader->setContentLength(docbody->buffer_length);
        }
    } else {
        docbody->swapbacktocompressed();
        // if we've not modified it might as well go back to
        // the original compressed version (if there) and send
        // that to the browser
    }
#ifdef DGDEBUG
    std::cerr << thread_id << " Returning from content checking"  << std::endl;
#endif
    }



int ConnectionHandler::sendProxyConnect(String &hostname, Socket *sock, NaughtyFilter *checkme)
{
    String connect_request = "CONNECT " + hostname + ":";
    connect_request += "443 HTTP/1.1\r\n\r\n";

#ifdef DGDEBUG
    std::cerr << thread_id << " -creating tunnel through proxy to " << hostname << std::endl;
#endif

    //somewhere to hold the header from the proxy
    HTTPHeader header(__HEADER_RESPONSE);
    //header.setTimeout(o.pcon_timeout);
    header.setTimeout(o.proxy_timeout);

        if(! (sock->writeString(connect_request.c_str())  &&  header.in(sock, true )) )  {

#ifdef DGDEBUG
        syslog(LOG_ERR, "Error creating tunnel through proxy\n");
        std::cerr << thread_id << " -Error creating tunnel through proxy" << strerror(errno) << std::endl;
#endif
        //(*checkme).whatIsNaughty = "Unable to create tunnel through local proxy";
        checkme->message_no = 157;
        (*checkme).whatIsNaughty = o.language_list.getTranslation(157);
        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
        (*checkme).isItNaughty = true;
        (*checkme).whatIsNaughtyCategories = o.language_list.getTranslation(70);

        return -1;
    }
    //do http connect
    if (header.returnCode() != 200) {
        //connection failed
        //(*checkme).whatIsNaughty = "Opening tunnel failed";
        checkme->message_no = 158;
        (*checkme).whatIsNaughty = o.language_list.getTranslation(158);
        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty + " with errror code " + String(header.returnCode());
        (*checkme).isItNaughty = true;
        (*checkme).whatIsNaughtyCategories = o.language_list.getTranslation(70);

#ifdef DGDEBUG
        syslog(LOG_ERR, "Tunnel status not 200 ok aborting\n");
        std::cerr << thread_id << " -Tunnel status was " << header.returnCode() << " expecting 200 ok" << std::endl;
#endif

        return -1;
    }

    return 0;
}

#ifdef __SSLMITM
void ConnectionHandler::checkCertificate(String &hostname, Socket *sslsock, NaughtyFilter *checkme)
{

#ifdef DGDEBUG
    std::cerr << thread_id << " -checking SSL certificate is valid" << std::endl;
#endif

    long rc = sslsock->checkCertValid();
    //check that everything in this certificate is correct appart from the hostname
    if (rc < 0) {
        //no certificate
        if ( ldl->fg[filtergroup]->allow_empty_host_certs)
            return;
        checkme->isItNaughty = true;
        //(*checkme).whatIsNaughty = "No SSL certificate supplied by server";
        checkme->message_no = 155;
        (*checkme).whatIsNaughty = o.language_list.getTranslation(155);
        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
        (*checkme).whatIsNaughtyCategories = o.language_list.getTranslation(70);
        return;
    } else if (rc != X509_V_OK) {
        //something was wrong in the certificate
        checkme->isItNaughty = true;
        //		(*checkme).whatIsNaughty = "Certificate supplied by server was not valid";
        checkme->message_no = 150;
        (*checkme).whatIsNaughty = o.language_list.getTranslation(150);
        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty + ": " + X509_verify_cert_error_string(rc);
        (*checkme).whatIsNaughtyCategories = o.language_list.getTranslation(70);
        return;
    }

#ifdef DGDEBUG
    std::cerr << thread_id << " -checking SSL certificate hostname" << std::endl;
#endif

    //check the common name and altnames of a certificate against hostname
    if (sslsock->checkCertHostname(hostname) < 0) {
        //hostname was not matched by the certificate
        checkme->isItNaughty = true;
        //(*checkme).whatIsNaughty = "Server's SSL certificate does not match domain name";
        checkme->message_no = 156;
        (*checkme).whatIsNaughty = o.language_list.getTranslation(156);
        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty;
        (*checkme).whatIsNaughtyCategories = o.language_list.getTranslation(70);
        return;
    }
}
#endif //__SSLMITM


bool ConnectionHandler::getdnstxt(std::string &clientip, String &user)
{

    String ippath;

    ippath = clientip;
//    if (o.use_xforwardedfor) {
//        // grab the X-Forwarded-For IP if available
//        p2 = header.getXForwardedForIP();
//        if (p2.length() > 0) {
//            ippath = p1 + "-" + p2;
//        } else {
//            ippath = p1;
//        }
//    } else {
//        ippath = p1;
//    }

#ifdef DGDEBUG
    std::cerr << "IPPath is " << ippath << std::endl;
#endif

    // change '.' to '-'
    ippath.swapChar('.', '-');
#ifdef DGDEBUG
    std::cerr << "IPPath is " << ippath << std::endl;
#endif

    // get info from DNS
    union {
        HEADER hdr;
        u_char buf[NS_PACKETSZ];
    } response;
    int responseLen;
#ifdef PRT_DNSAUTH
    ns_msg handle; /* handle for response message */
    responseLen = res_querydomain(ippath.c_str(), o.dns_user_logging_domain.c_str(), ns_c_in, ns_t_txt, (u_char *)&response, sizeof(response));
    if (responseLen < 0) {
#ifdef DGDEBUG
        std::cerr << "DNS query returned error " << dns_error(h_errno) << std::endl;
#endif
        return false;
    }
    if (ns_initparse(response.buf, responseLen, &handle) < 0) {
#ifdef DGDEBUG
        std::cerr << "ns_initparse returned error " << strerror(errno) << std::endl;
#endif
        return false;
    }
    int rrnum; /* resource record number */
    ns_rr rr; /* expanded resource record */
    u_char *cp;
    char ans[MAXDNAME];

    int i = ns_msg_count(handle, ns_s_an);
    if (i > 0) {
        if (ns_parserr(&handle, ns_s_an, 0, &rr)) {
#ifdef DGDEBUG
            std::cerr << "ns_paserr returned error " << strerror(errno) << std::endl;
#endif
            return false;
        } else {
            if (ns_rr_type(rr) == ns_t_txt) {
#ifdef DGDEBUG
                std::cerr << "ns_rr_rdlen returned " << ns_rr_rdlen(rr) << std::endl;
#endif
                u_char *k = (u_char *)ns_rr_rdata(rr);
                char p[400];
                unsigned int j = 0;
                for (unsigned int j1 = 1; j1 < ns_rr_rdlen(rr); j1++) {
                    p[j++] = k[j1];
                }
//                p[j] = (char)NULL;
                p[j] = '\0';
#ifdef DGDEBUG
                std::cerr << "ns_rr_data returned " << p << std::endl;
#endif
                String dnstxt(p);
                user = dnstxt.before(",");
                return true;
            }
        }
    }
#endif
    return false;
}

String ConnectionHandler::dns_error(int herror)
{

    String s;

    switch (herror) {
        case HOST_NOT_FOUND:
            s = "HOST_NOT_FOUND";
            break;
        case TRY_AGAIN:
            s = "TRY_AGAIN - DNS server failure";
            break;
        case NO_DATA:
            s = "NO_DATA - unexpected DNS error";
            break;
        default:
            String S2(herror);
            s = "DNS - Unexpected error number " + S2;
            break;
    }
    return s;
}

bool ConnectionHandler::gen_error_mess( Socket &peerconn, NaughtyFilter &cm, String &eheader, String &ebody, int mess_no1, int mess_no2, std::string mess) {
    cm.message_no = mess_no1;
    eheader = "HTTP/1.1 " + mess +"\nContent-Type: text/html\r\n";
    ebody =  "<HTML><HEAD><TITLE>e2guardian - ";
    ebody += mess;
    ebody += "</TITLE></HEAD><BODY><H1>e2guardian - ";
    ebody += mess;
    ebody += "</H1>";
    if (mess_no1 > 0)
        ebody += o.language_list.getTranslation(mess_no1);
    if (mess_no2 > 0)
    ebody += o.language_list.getTranslation(mess_no2);
    ebody += "</BODY></HTML>\r\n";
    return true;
}

bool ConnectionHandler::writeback_error( NaughtyFilter &cm, Socket & cl_sock, int mess_no1, int mess_no2, std::string mess) {
    String eheader, ebody;
    gen_error_mess(cl_sock, cm, eheader, ebody, mess_no1, mess_no2, mess);
    cl_sock.writeString(eheader.c_str());
    cl_sock.writeString(ebody.c_str());
    return true;
}

#ifdef __SSLMITM
bool ConnectionHandler::goMITM(NaughtyFilter &checkme, Socket &proxysock, Socket &peerconn, bool &persistProxy, bool &authed,
                          bool &persistent_authed, String &ip, stat_rec *&dystat, std::string &clientip,
                          bool transparent) {
#ifdef DGDEBUG
        std::cerr << thread_id << " Start goMITM nf " << checkme.isItNaughty <<
                " upfail " << checkme.upfailure << std::endl;
#endif


#ifdef DGDEBUG
    std::cerr << thread_id << " -Intercepting HTTPS connection" << std::endl;
#endif
    HTTPHeader *header = checkme.request_header;
    HTTPHeader *docheader = checkme.response_header;

//Do the connect request - already done

//  CA intialisation now Moved into OptionContainer so now done once on start-up
//  instead off on every request

    X509 *cert = NULL;
    struct ca_serial caser;
    caser.asn = NULL;
    caser.charhex = NULL;
    caser.filepath = NULL;
    caser.filename = NULL;

    EVP_PKEY *pkey = NULL;
    bool certfromcache = false;
//generate the cert
#ifdef DGDEBUG
        std::cerr << thread_id << " -Getting ssl certificate for client connection" << std::endl;
#endif

        pkey = o.ca->getServerPkey();

//generate the certificate but dont write it to disk (avoid someone
//requesting lots of places that dont exist causing the disk to fill
//up / run out of inodes
        certfromcache = o.ca->getServerCertificate(checkme.urldomain.CN().c_str(), &cert,
                                                   &caser);
#ifdef DGDEBUG
        if (caser.asn == NULL) {
                                std::cerr << "caser.asn is NULL" << std::endl;
                            }
        //				std::cerr << "serials are: " << (char) *caser.asn << " " < caser.charhex  << std::endl;
#endif

//check that the generated cert is not null and fillin checkme if it is
        if (cert == NULL) {
            checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to get ssl certificate";
            checkme.message_no = 151;
            checkme.whatIsNaughty = o.language_list.getTranslation(151);
            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
        } else if (pkey == NULL) {
            checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to load ssl private key";
            checkme.message_no = 153;
            checkme.whatIsNaughty = o.language_list.getTranslation(153);
            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
        }

//startsslserver on the connection to the client
    //if (!checkme.isItNaughty)
    if (true)
    {
#ifdef DGDEBUG
        std::cerr << thread_id << " -Going SSL on the peer connection" << std::endl;
#endif

        if (!transparent) {
//send a 200 to the client no matter what because they managed to get a connection to us
//and we can use it for a blockpage if nothing else
            std::string msg = "HTTP/1.1 200 Connection established\r\n\r\n";
            if (!peerconn.writeString(msg.c_str()))
                cleanThrow("Unable to send to client 1670", peerconn);
        }

        if (peerconn.startSslServer(cert, pkey, o.set_cipher_list) < 0) {
//make sure the ssl stuff is shutdown properly so we display the old ssl blockpage
            peerconn.stopSsl();

            checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to negotiate ssl connection to client";
            checkme.message_no = 154;
            checkme.whatIsNaughty = o.language_list.getTranslation(154);
            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
        }
    }

    bool badcert = false;

    if (proxysock.isOpen()) {
// tsslclient connected to the proxy and check the certificate of the server
#ifdef DGDEBUG
        std::cerr << thread_id << " nf " << checkme.isItNaughty <<
                " upfail " << checkme.upfailure << std::endl;
#endif
        if (!checkme.isItNaughty) {
#ifdef DGDEBUG
            std::cerr << thread_id << " -Going SSL on upstream connection " << std::endl;
#endif
            std::string certpath = std::string(o.ssl_certificate_path);
            if (proxysock.startSslClient(certpath, checkme.urldomain)) {
//make sure the ssl stuff is shutdown properly so we display the old ssl blockpage
//    proxysock.stopSsl();

                checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to negotiate ssl connection to server";
                checkme.message_no = 160;
                checkme.whatIsNaughty = o.language_list.getTranslation(160);
                checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
            }
        }
#ifdef DGDEBUG
        std::cerr << thread_id << " nf " << checkme.isItNaughty <<
                " upfail " << checkme.upfailure << std::endl;
#endif

        if (!checkme.isItNaughty) {

#ifdef DGDEBUG
            std::cerr << thread_id << " -Checking certificate" << std::endl;
#endif
//will fill in checkme of its own accord
            if (!checkme.nocheckcert) {
                checkCertificate(checkme.urldomain, &proxysock, &checkme);
                badcert = checkme.isItNaughty;
            }
        }
    }

#ifdef DGDEBUG
        std::cerr << thread_id << " nf " << checkme.isItNaughty <<
                " upfail " << checkme.upfailure << std::endl;
#endif
//handleConnection inside the ssl tunnel
    if ((!checkme.isItNaughty) && (!checkme.upfailure)) {
        bool writecert = true;
        if (!certfromcache) {
            writecert = o.ca->writeCertificate(checkme.urldomain.c_str(), cert,
                                               &caser);
        }

//if we cant write the certificate its not the end of the world but it is slow
        if (!writecert) {
#ifdef DGDEBUG
            std::cerr << thread_id << " -Couldn't save certificate to on disk cache" << std::endl;
#endif
            syslog(LOG_ERR, "Couldn't save certificate to on disk cache");
        }
#ifdef DGDEBUG
        std::cerr << thread_id << " -Handling connections inside ssl tunnel" << std::endl;
#endif

        if (authed) {
            persistent_authed = true;
        }

        handleConnection(peerconn, ip, true, proxysock, dystat);
#ifdef DGDEBUG
        std::cerr << thread_id << " -Handling connections inside ssl tunnel: done" << std::endl;
#endif
    }
    o.ca->free_ca_serial(&caser);

//stopssl on the proxy connection
//if it was marked as naughty then show a deny page and close the connection
    if (checkme.isItNaughty || checkme.upfailure) {
#ifdef DGDEBUG
        std::cerr << thread_id << " -SSL Interception failed " << checkme.whatIsNaughty << " nf " << checkme.isItNaughty <<
                " upfail " << checkme.upfailure << std::endl;
#endif

        doLog(clientuser, clientip, checkme);

        denyAccess(&peerconn, &proxysock, header, docheader, &checkme.logurl, &checkme, &clientuser,
                   &clientip, filtergroup, checkme.ispostblock, checkme.headersent, checkme.wasinfected,
                   checkme.scanerror, badcert);
    }
#ifdef DGDEBUG
    std::cerr << thread_id << " -Shutting down ssl to proxy" << std::endl;
#endif
    proxysock.stopSsl();

#ifdef DGDEBUG
    std::cerr << thread_id << " -Shutting down ssl to client" << std::endl;
#endif

    peerconn.stopSsl();

//tidy up key and cert
    X509_free(cert);
    EVP_PKEY_free(pkey);

    persistProxy = false;
    proxysock.close();
    return true; // this fixes illegal instruction on BSD but is this the best return for this bool function?
}
#endif

bool ConnectionHandler::doAuth(bool &authed, int &filtergroup,AuthPlugin* auth_plugin, Socket & peerconn,  HTTPHeader & header, bool only_client_ip) {
    Socket nullsock;
    return doAuth(authed, filtergroup, auth_plugin, peerconn, nullsock, header, only_client_ip);
}

bool ConnectionHandler::doAuth(bool &authed, int &filtergroup,AuthPlugin* auth_plugin, Socket & peerconn, Socket &proxysock, HTTPHeader & header, bool only_client_ip) {

#ifdef DGDEBUG
                std::cerr << thread_id << " -Not got persistent credentials for this connection - querying auth plugins" << std::endl;
#endif
                bool dobreak = false;
                if (o.authplugins.size() != 0) {
                    // We have some auth plugins load
                    int authloop = 0;
                    int rc;
                    String tmp;

                    for (std::deque<Plugin *>::iterator i = o.authplugins_begin; i != o.authplugins_end; i++) {
#ifdef DGDEBUG
                        std::cerr << thread_id << " -Querying next auth plugin..." << std::endl;
#endif
                        // try to get the username & parse the return value
                        auth_plugin = (AuthPlugin *) (*i);
                        if (only_client_ip && !auth_plugin->client_ip_based)
                            continue;

                        // auth plugin selection for multi ports
                        //
                        //
                        // Logic changed to allow auth scan with multiple ports as option to auth-port
                        //       fixed mapping
                        //
                        if (o.map_auth_to_ports) {
                            if (o.filter_ports.size() > 1) {
                                tmp = o.auth_map[peerconn.getPort()];
                            } else {
                                // auth plugin selection for one port
                                tmp = o.auth_map[authloop];
                                authloop++;
                            }

                            if (tmp.compare(auth_plugin->getPluginName().toCharArray()) == 0) {
                                rc = auth_plugin->identify(peerconn, proxysock, header, clientuser, is_real_user);
                            } else {
                                rc = DGAUTH_NOMATCH;
                            }
                        } else {
                            rc = auth_plugin->identify(peerconn, proxysock, header, clientuser, is_real_user);
                        }

                        if (rc == DGAUTH_NOMATCH) {
#ifdef DGDEBUG
                            std::cerr << "Auth plugin did not find a match; querying remaining plugins" << std::endl;
#endif
                            continue;
                        } else if (rc == DGAUTH_REDIRECT) {
#ifdef DGDEBUG
                            std::cerr << "Auth plugin told us to redirect client to \"" << clientuser << "\"; not querying remaining plugins" << std::endl;
#endif
                            // ident plugin told us to redirect to a login page
                            String writestring("HTTP/1.1 302 Redirect\r\nLocation: ");
                            writestring += clientuser;
                            writestring += "\r\n\r\n";
                            peerconn.writeString(writestring.toCharArray());   // no action on failure
                            dobreak = true;
                            break;
                        } else if (rc == DGAUTH_OK_NOPERSIST) {
#ifdef DGDEBUG
                            std::cerr << "Auth plugin  returned OK but no persist not setting persist auth" << std::endl;
#endif
                            overide_persist = true;
                        } else if (rc < 0) {
                            if (!is_daemonised)
                                std::cerr << thread_id << "Auth plugin returned error code: " << rc << std::endl;
                            syslog(LOG_ERR, "%sAuth plugin returned error code: %d", thread_id.c_str(), rc);
                            dobreak = true;
                            break;
                        }
#ifdef DGDEBUG
                        std::cerr << thread_id << " -Auth plugin found username " << clientuser << " (" << oldclientuser << "), now determining group" << std::endl;
#endif
                        if (clientuser == oldclientuser) {
#ifdef DGDEBUG
                            std::cerr << thread_id << " -Same user as last time, re-using old group no." << std::endl;
#endif
                            authed = true;
                            filtergroup = oldfg;
                            break;
                        }
                        // try to get the filter group & parse the return value
                        rc = auth_plugin->determineGroup(clientuser, filtergroup, ldl->filter_groups_list);
                        if (rc == DGAUTH_OK) {
#ifdef DGDEBUG
                            std::cerr << thread_id << "Auth plugin found username & group; not querying remaining plugins" << std::endl;
#endif
                            authed = true;
                            break;
                        } else if (rc == DGAUTH_NOMATCH) {
#ifdef DGDEBUG
                            std::cerr << thread_id << "Auth plugin did not find a match; querying remaining plugins" << std::endl;
#endif
                            continue;
                        } else if (rc == DGAUTH_NOUSER) {
#ifdef DGDEBUG
                            std::cerr << thread_id << "Auth plugin found username \"" << clientuser << "\" but no associated group; not querying remaining plugins" << std::endl;
#endif
                            if (o.auth_requires_user_and_group)
                                continue;
                            //filtergroup = 0; //default group - one day configurable? - default now set before call to doAuth
                            authed = true;
                            break;
                        } else if (rc < 0) {
                            if (!is_daemonised)
                                std::cerr << thread_id << "Auth plugin returned error code: " << rc << std::endl;
                            syslog(LOG_ERR, "%sAuth plugin returned error code: %d", thread_id.c_str(), rc);
                            dobreak = true;
                            break;
                        }
                    } // end of querying all plugins (for)

                    // break the peer loop
                    if (dobreak)
                        return false;
                    //break;

                    if ((!authed) || (filtergroup < 0) || (filtergroup >= o.numfg)) {
#ifdef DGDEBUG
                        if (!authed)
                            std::cerr << thread_id << " -No identity found; using defaults" << std::endl;
                        else
                            std::cerr << thread_id << " -Plugin returned out-of-range filter group number; using defaults" << std::endl;
#endif
                        // If none of the auth plugins currently loaded rely on querying the proxy,
                        // such as 'ident' or 'ip', then pretend we're authed. What this flag
                        // actually controls is whether or not the query should be forwarded to the
                        // proxy (without pre-emptive blocking); we don't want this for 'ident' or
                        // 'ip', because Squid isn't necessarily going to return 'auth required'.
                        authed = !o.auth_needs_proxy_query;
#ifdef DGDEBUG
                        if (!o.auth_needs_proxy_query)
                            std::cerr << thread_id << " -No loaded auth plugins require parent proxy queries; enabling pre-emptive blocking despite lack of authentication" << std::endl;
#endif
                        clientuser = "-";
                        //filtergroup = 0; //default group - one day configurable? - default now set before call to doAuth
                    } else {
#ifdef DGDEBUG
                        std::cerr << thread_id << " -Identity found; caching username & group" << std::endl;
#endif
                        if (auth_plugin->is_connection_based && !overide_persist) {
#ifdef DGDEBUG
                            std::cerr << "Auth plugin is for a connection-based auth method - keeping credentials for entire connection" << std::endl;
#endif
                            persistent_authed = true;
                        }
                        oldclientuser = clientuser;
                        oldfg = filtergroup;
                    }
                } else {
// We don't have any auth plugins loaded
#ifdef DGDEBUG
                    std::cerr << thread_id << " -No auth plugins loaded; using defaults & feigning persistency" << std::endl;
#endif
                    authed = true;
                    clientuser = "-";
                    //filtergroup = 0; //default group - one day configurable? - default now set before call to doAuth
                    persistent_authed = true;
                }
    return true;
}

bool ConnectionHandler::checkByPass( NaughtyFilter &checkme, std::shared_ptr<LOptionContainer> & ldl, HTTPHeader &header, Socket & proxysock, Socket &peerconn, std::string &clientip ) {

    //first check if bypass allowed and set isbypassallowed
    checkme.isbypassallowed = (ldl->fg[filtergroup]->bypass_mode != 0);
    checkme.isinfectionbypassallowed= (ldl->fg[filtergroup]->infection_bypass_mode != 0);
    if (!(checkme.isbypassallowed || checkme.isinfectionbypassallowed))
        return false;

   // int bypasstimestamp = 0;
    if (header.isScanBypassURL(checkme.url, ldl->fg[filtergroup]->magic.c_str(), clientip.c_str())) {
#ifdef DGDEBUG
        std::cerr << thread_id << " -Scan Bypass URL match" << std::endl;
#endif
        checkme.isscanbypass = true;
        checkme.isbypass = true;
        checkme.message_no = 608;
        checkme.log_message_no = 608;
        checkme.exceptionreason = o.language_list.getTranslation(608);
    } else if ((ldl->fg[filtergroup]->bypass_mode != 0) || (ldl->fg[filtergroup]->infection_bypass_mode != 0)) {
#ifdef DGDEBUG
        std::cerr << thread_id << " -About to check for bypass..." << std::endl;
#endif
        if (ldl->fg[filtergroup]->bypass_mode != 0)
            checkme.bypasstimestamp = header.isBypassURL(checkme.url, ldl->fg[filtergroup]->magic.c_str(),
                                                 clientip.c_str(), NULL);
        if ((checkme.bypasstimestamp == 0) && (ldl->fg[filtergroup]->infection_bypass_mode != 0))
            checkme.bypasstimestamp = header.isBypassURL(checkme.url, ldl->fg[filtergroup]->imagic.c_str(),
                                                 clientip.c_str(), &checkme.isvirusbypass);
        if (checkme.bypasstimestamp > 0) {
#ifdef DGDEBUG
            if (checkme.isvirusbypass)
                std::cerr << thread_id << " -Infection bypass URL match" << std::endl;
            else
                std::cerr << thread_id << " -Filter bypass URL match" << std::endl;
#endif
            header.chopBypass(checkme.logurl, checkme.isvirusbypass);
            if (checkme.bypasstimestamp > 1) { // not expired
                checkme.isbypass = true;
                checkme.isexception = true;
                // checkme: need a TR string for virus bypass
                checkme.exceptionreason = o.language_list.getTranslation(606);
                checkme.message_no = 606;
                checkme.log_message_no = 606;
            }
        } else if (ldl->fg[filtergroup]->bypass_mode != 0) {
            if (header.isBypassCookie(checkme.urldomain, ldl->fg[filtergroup]->cookie_magic.c_str(),
                                      clientip.c_str())) {
#ifdef DGDEBUG
                std::cerr << thread_id << " -Bypass cookie match" << std::endl;
#endif
                checkme.iscookiebypass = true;
                checkme.isbypass = true;
                checkme.isexception = true;
                checkme.exceptionreason = o.language_list.getTranslation(607);
            }
        }
#ifdef DGDEBUG
        std::cerr << thread_id << " -Finished bypass checks." << std::endl;
#endif
    }

#ifdef DGDEBUG
    if (checkme.isbypass) {
        std::cerr << thread_id << " -bypass activated!" << std::endl;
    }
#endif
    //
// End of bypass
//
// Start of scan by pass
//

    if (checkme.isscanbypass) {
//we need to decode the URL and send the temp file with the
        //correct header to the client then delete the temp file
        checkme.tempfilename = (checkme.url.after("GSBYPASS=").after("&N="));
        checkme.tempfilemime = (checkme.tempfilename.after("&M="));
        checkme.tempfiledis = (header.decode(checkme.tempfilemime.after("&D="), true));
#ifdef DGDEBUG
        std::cerr << thread_id << " -Original filename: " << checkme.tempfiledis << std::endl;
#endif
        String rtype(header.requestType());
        checkme.tempfilemime = checkme.tempfilemime.before("&D=");
        checkme.tempfilename = o.download_dir + "/tf" + checkme.tempfilename.before("&M=");
        return true;
    }
    return false;
}

bool ConnectionHandler::sendScanFile( Socket &peerconn, NaughtyFilter &checkme, bool is_icap, ICAPHeader *icaphead)
{
        try {
        checkme.docsize = sendFile(&peerconn, checkme, checkme.url, is_icap, icaphead);
        checkme.request_header->chopScanBypass(checkme.url);
        checkme.logurl = checkme.request_header->getLogUrl();

        doLog(clientuser, checkme.clientip, checkme );

    if (o.delete_downloaded_temp_files) {
        unlink(checkme.tempfilename.toCharArray() );
        }
    } catch (
        std::exception &e
    ) {
    }
     //   persistProxy = false;
     //   proxysock.close(); // close connection to proxy
        return true;
}

void ConnectionHandler::check_search_terms(NaughtyFilter &cm) {
    if (ldl->fg[filtergroup]->searchterm_limit > 0) {
        String terms;
        terms = cm.search_terms;
// search terms are URL parameter type "0"
        urlparams.append("0=").append(terms).append(";");
// Add spaces at beginning and end of block before filtering, so
// that the quick & dirty trick of putting spaces around words
// (Scunthorpe problem) can still be used, bearing in mind the block
// of text here is usually very small.
            terms.insert(terms.begin(), ' ');
            terms.append(" ");
            cm.checkme(terms.c_str(), terms.length(), NULL, NULL, ldl->fg[filtergroup],
                             (ldl->fg[filtergroup]->searchterm_flag ? ldl->fg[filtergroup]->searchterm_list : ldl->fg[filtergroup]->banned_phrase_list),
                             ldl->fg[filtergroup]->searchterm_limit, true);
            if (cm.isItNaughty) {
                cm.blocktype = 2;
            }
        }
    return;
}

void ConnectionHandler::check_content(NaughtyFilter &cm, DataBuffer &docbody, Socket &proxysock, Socket &peerconn,
std::deque<CSPlugin *> &responsescanners)
{
    if (((cm.response_header->isContentType("text",ldl->fg[filtergroup]) || cm.response_header->isContentType("-",ldl->fg[filtergroup])) && !cm.isexception) || !responsescanners.empty()) {
        cm.waschecked = true;
        if (!responsescanners.empty()) {
#ifdef DGDEBUG
            std::cerr << thread_id << " -Filtering with expectation of a possible csmessage" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            String csmessage;
            contentFilter(cm.response_header, cm.request_header, &docbody, &proxysock, &peerconn, &cm.headersent, &cm.pausedtoobig,
                          &cm.docsize, &cm, cm.wasclean, filtergroup, responsescanners, &clientuser, &cm.clientip,
                          &cm.wasinfected, &cm.wasscanned, cm.isbypass, cm.urld, cm.urldomain, &cm.scanerror, cm.contentmodified, &csmessage);
            if (csmessage.length() > 0) {
#ifdef DGDEBUG
                std::cerr << thread_id << " -csmessage found: " << csmessage << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                cm.exceptionreason = csmessage.toCharArray();
            }
        } else {
#ifdef DGDEBUG
            std::cerr << thread_id << " -Calling contentFilter " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            contentFilter(cm.response_header, cm.request_header, &docbody, &proxysock, &peerconn, &cm.headersent, &cm.pausedtoobig,
                          &cm.docsize, &cm, cm.wasclean, filtergroup, responsescanners, &clientuser, &cm.clientip,
                          &cm.wasinfected, &cm.wasscanned, cm.isbypass, cm.urld, cm.urldomain, &cm.scanerror, cm.contentmodified, NULL);
        }
    } else {
        cm.tunnel_rest = true;
    }
    std::cerr << thread_id << "End content check isitNaughty is  " << cm.isItNaughty << std::endl;
}

#ifdef __SSLMITM
int ConnectionHandler::handleTHTTPSConnection(Socket &peerconn, String &ip, Socket &proxysock, stat_rec* &dystat) {
    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    peerconn.setTimeout(o.pcon_timeout);

    HTTPHeader docheader(__HEADER_RESPONSE); // to hold the returned page header from proxy
    HTTPHeader header(__HEADER_REQUEST); // to hold the incoming client request headeri(ldl)

    NaughtyFilter checkme(header, docheader);
    checkme.reset();


    std::string clientip(ip.toCharArray()); // hold the clients ip
    docheader.setClientIP(ip);

    if (clienthost) delete clienthost;

    clienthost = NULL; // and the hostname, if available
    matchedip = false;


#ifdef DGDEBUG // debug stuff surprisingly enough
std::cerr << thread_id << " -got peer connection - clientip is " << clientip << std::endl;
#endif

    try {
        int rc;


        int oldfg = 0;
        bool authed = false;
        bool isbanneduser = false;
        bool firsttime = true;

        AuthPlugin *auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistOutgoing = true;
        bool persistPeer = true;
        bool persistProxy = false;
        bool direct = false;

        char buff[2048];
        rc = peerconn.readFromSocket(buff, 5, (MSG_PEEK ), 20000, true);
#ifdef DGDEBUG
            std::cerr << thread_id << "bytes peeked " << rc << std::endl;
#endif
        unsigned short toread;
        if (rc == 5) {
        if (buff[0] == 22 && buff[1] == 3 && buff[2] > 0 && buff[2] < 4 )   // has TLS hello signiture
            checkme.isTLS = true;

        toread = ( buff[3] << (8*1) | buff[4]);
        if (toread > 2048) toread = 2048;
        }

#ifdef DGDEBUG
        std::cerr << thread_id << "hello length is " << toread << " magic is " << buff[0]  << buff[1] << buff[2] << " isTLS is " << checkme.isTLS << std::endl;
#endif

       if(checkme.isTLS) {
            rc = peerconn.readFromSocket(buff, toread, (MSG_PEEK ), 10000, false);
            if (rc < 1 ) {     // get header from client, allowing persistency
                if (o.logconerror) {
                    if (peerconn.getFD() > -1) {

                        int err = peerconn.getErrno();
                        int pport = peerconn.getPeerSourcePort();
                        std::string peerIP = peerconn.getPeerIP();
                        if(peerconn.isTimedout())
                        {
    #ifdef DGDEBUG
                            std::cerr << thread_id << "Connection timed out" << std::endl;
    #endif
                            }
                        syslog(LOG_INFO, "%sNo header recd from client at %s - errno: %d", thread_id.c_str(), peerIP.c_str(), err);
    #ifdef DGDEBUG
                        std::cerr << thread_id << "No header recd from client - errno: " << err << std::endl;
    #endif
                    } else {
                        syslog(LOG_INFO, "%sClient connection closed early - no TLS header received",
                                thread_id.c_str() );
                    }
                }
            firsttime = false;
            persistPeer = false;
        } else {
#ifdef DGDEBUG
            std::cerr << thread_id << "bytes peeked " << rc << std::endl;
#endif
//            checkme.urldomain = get_TLS_SNI(buff, &rc);
//            if(checkme.urldomain.size() > 0)
//                checkme.hasSNI = true;
             char *ret = get_TLS_SNI(buff, &rc);
             if (ret != NULL) {
//             checkme.urldomain = ret;
             checkme.url = ret;
             checkme.hasSNI = true;
             }

            ++dystat->reqs;
        }
        }
        {   // get original IP destination & port

                sockaddr_in origaddr;
                socklen_t origaddrlen(sizeof(sockaddr_in));
                if (
#ifdef SOL_IP       // linux
#define SO_ORIGINAL_DST 80
                        getsockopt(peerconn.getFD(), SOL_IP, SO_ORIGINAL_DST, &origaddr, &origaddrlen ) < 0
#else                       // BSD
                        getsockname(peerconn.getFD(), (struct sockaddr *)&origaddr, &origaddrlen) < 0
#endif
                ) {
                    syslog(LOG_ERR, "%sFailed to get client's original destination IP: %s", thread_id.c_str(), strerror(errno));
                    return -1;
                } else {
                checkme.orig_ip = inet_ntoa(origaddr.sin_addr);
                checkme.orig_port = ntohs(origaddr.sin_port);
                }
         }

        if(!checkme.hasSNI) {
        checkme.url = checkme.orig_ip;
         }
#ifdef DGDEBUG
    std::cerr << thread_id << "hasSNI = " << checkme.hasSNI << " SNI is " << checkme.url <<  " Orig IP " << checkme.orig_ip << " Orig port " << checkme.orig_port << std::endl;
#endif
        //
        // End of set-up section

        while (firsttime )    // do just the once
        {
            ldl = o.currentLists();
            //DataBuffer docbody;
            //docbody.setTimeout(o.exchange_timeout);
            FDTunnel fdt;

                firsttime = false;

//
            // do all of this normalisation etc just the once at the start.
            checkme.url = "https://" + checkme.url;
            checkme.setURL(checkme.url);
            gettimeofday(&checkme.thestart, NULL);

            if(checkme.isconnect) {
            persistPeer = false;
            persistOutgoing = false;
            }

            // do total block list checking here
            //if (o.use_total_block_list && o.inTotalBlockList(checkme.urld)) {     // not sure if we should do this here!!!!
                //proxysock.close(); // close connection to proxy
                //break;
            //}

            //
            //
            // Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            overide_persist = false;
            filtergroup = o.default_trans_fg;
                if (!doAuth(authed, filtergroup, auth_plugin,  peerconn, proxysock,  header, true) )
                    break;
            checkme.filtergroup = filtergroup;

#ifdef DGDEBUG
            std::cerr << thread_id << " -username: " << clientuser << " -filtergroup: " << filtergroup << std::endl;
#endif
//
//
// End of Authentication Checking
//
//

            //
            //
            // Now check if user or machine is banned and room-based checking
            //
            //

            // is this user banned?
            isbanneduser = false;
            checkme.clientip = clientip;

            // Look up reverse DNS name of client if needed
            if (o.reverse_client_ip_lookups) {
                std::unique_ptr<std::deque<String> > hostnames;
                    hostnames.reset(ipToHostname(clientip.c_str()));
                    checkme.clienthost = std::string(hostnames->front().toCharArray());
            }

            checkme.ismitmcandidate = ldl->fg[filtergroup]->ssl_mitm;

            //CALL SB pre-authcheck
            ldl->StoryA.runFunctEntry(ENT_STORYA_PRE_AUTH_THTTPS,checkme);
#ifdef DGDEBUG
            std::cerr << thread_id << "After StoryA thttps-pre-authcheck" << checkme.isexception << " mess_no "
                      << checkme.message_no << std::endl;
#endif
            checkme.isItNaughty = checkme.isBlocked;
            bool isbannedip = checkme.isBlocked;
            bool part_banned;

            // TODO restore this for THTTPS ??
            //if (isbannedip) {
               // matchedip = clienthost == NULL;
            //} else {
            // /   if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
            // /                   checkme.urld)) {
#ifdef DGDEBUG
            // /       std::cerr << " isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << checkme.isexception << std::endl;
#endif
          //.          if (isbannedip) {
                 //       matchedip = clienthost == NULL;
            //            checkme.isBlocked = checkme.isItNaughty = true;
            // /       }
            //        if (checkme.isexception) {
                        // do reason codes etc
                        //checkme.exceptionreason = o.language_list.getTranslation(630);
                        //checkme.exceptionreason.append(room);
                        //checkme.exceptionreason.append(o.language_list.getTranslation(631));
                        //checkme.message_no = 632;
                    //}
                //}
            //}

            char *retchar;

            //
            // Start of exception checking
            //
            // being a banned user/IP overrides the fact that a site may be in the exception lists
            // needn't check these lists in bypass modes
            if (!(isbanneduser || isbannedip || checkme.isexception)) {
                    ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_THTTPS_REQUEST,checkme);
#ifdef DGDEBUG
                    std::cerr << thread_id << "After StoryB thttps-checkrequest " << checkme.isexception << " mess_no "
                              << checkme.message_no << std::endl;
#endif
                    checkme.isItNaughty = checkme.isBlocked;
            }

            //now send upstream and get response
            if (!checkme.isItNaughty && !persistProxy) {
                if (connectUpstream(proxysock, checkme,443) > -1) {
                    if(!checkme.isdirect) {
                        if (sendProxyConnect(checkme.connect_site,&proxysock, &checkme) != 0)
                       checkme.upfailure = true;
                    }
                } else {
                       checkme.upfailure = true;
                }
            }

#ifdef DGDEBUG
        std::cerr << thread_id << " after connectUpstream nf " << checkme.isItNaughty <<
                " upfail " << checkme.upfailure << std::endl;
#endif

            if((checkme.isItNaughty ||checkme.upfailure) && ldl->fg[filtergroup]->ssl_mitm) checkme.gomitm = true;  // allows us to send splash page

            if (checkme.isexception && !checkme.upfailure) {
                    checkme.tunnel_rest = true;
             } else {

            //if ismitm - GO MITM
                if (checkme.gomitm)
                {
#ifdef DGDEBUG
                std::cerr << thread_id << "Going MITM ...." << std::endl;
#endif
                if(!ldl->fg[filtergroup]->mitm_check_cert)
                    checkme.nocheckcert = true;
                goMITM(checkme, proxysock, peerconn, persistProxy, authed, persistent_authed, ip, dystat, clientip, true);
                persistPeer = false;
                persistProxy = false;
                if (!checkme.isItNaughty)
                    break;
                } else {
                if (!checkme.upfailure)
                    checkme.tunnel_rest = true;
                }
            }

            //if not grey tunnel response
            if (!checkme.isItNaughty && checkme.tunnel_rest) {
#ifdef DGDEBUG
                std::cerr << thread_id << " -Tunnelling to client" << std::endl;
#endif
                if (!fdt.tunnel(proxysock, peerconn,true, -1 , true))
                    persistProxy = false;
                checkme.docsize += fdt.throughput;
            }

            if(checkme.isItNaughty) {
                if(denyAccess(&peerconn,&proxysock, &header, &docheader, &checkme.url, &checkme, &clientuser, &clientip,
                           filtergroup, checkme.ispostblock,checkme.headersent, checkme.wasinfected, checkme.scanerror))
                    persistPeer = false;
            }

            //Log
            if (!checkme.isourwebserver) { // don't log requests to the web server
                doLog(clientuser, clientip, checkme);
            }


                proxysock.close(); // close connection to proxy


        }
        } catch (std::exception & e)
        {
#ifdef DGDEBUG
        std::cerr << thread_id << " - THTTPS connection handler caught an exception: " << e.what() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        if(o.logconerror)
            syslog(LOG_ERR, " - THTTPS connection handler caught an exception %s" , e.what());

        // close connection to proxy
        proxysock.close();
            return -1;
        }

    return 0;
}


char *get_TLS_SNI(char *inbytes, int* len)
{
    unsigned char *bytes = reinterpret_cast<unsigned char*>(inbytes);
    unsigned char *curr;
    unsigned char *ebytes;
     ebytes = bytes + *len;
    if (*len < 44) return NULL;
    unsigned char sidlen = bytes[43];
    curr = bytes + 1 + 43 + sidlen;
    if (curr > ebytes) return NULL;
    unsigned short cslen = ntohs(*(unsigned short*)curr);
    curr += 2 + cslen;
    if (curr > ebytes) return NULL;
    unsigned char cmplen = *curr;
    curr += 1 + cmplen;
    if (curr > ebytes) return NULL;
    unsigned char *maxchar = curr + 2 + ntohs(*(unsigned short*)curr);
    curr += 2;
    unsigned short ext_type = 1;
    unsigned short ext_len;
    while(curr < maxchar && ext_type != 0)
    {
        if (curr > ebytes) return NULL;
        ext_type = ntohs(*(unsigned short*)curr);
        curr += 2;
        if (curr > ebytes) return NULL;
        ext_len = ntohs(*(unsigned short*)curr);
        curr += 2;
        if(ext_type == 0)
        {
            curr += 3;
            if (curr > ebytes) return NULL;
            unsigned short namelen = ntohs(*(unsigned short*)curr);
            curr += 2;
            if ((curr + namelen) > ebytes) return NULL;
            //*len = namelen;
            *(curr +namelen) = (char)0;
            return (char*)curr;
        }
        else curr += ext_len;
    }
    //if (curr != maxchar) throw std::exception("incomplete SSL Client Hello");
    return NULL; //SNI was not present
}

#endif


int ConnectionHandler::handleICAPConnection(Socket &peerconn, String &ip, Socket &proxysock, stat_rec* &dystat) {

    int pcount = 0;
    bool ismitm = false;

    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    peerconn.setTimeout(o.pcon_timeout);

    std::string clientip(ip.toCharArray()); // hold the ICAP clients ip

    if (clienthost) delete clienthost;

    clienthost = NULL; // and the hostname, if available
    matchedip = false;

    //try {
        int rc;


        int oldfg = 0;
        bool authed = false;
        bool isbanneduser = false;
        bool firsttime = true;

        AuthPlugin *auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistPeer = true;

        //
        // End of set-up section

        // Start of main loop

        //

        // maintain a persistent connection
        while ((firsttime || persistPeer) && !ttg)
        {
            ICAPHeader icaphead;
            ldl = o.currentLists();
            icaphead.ISTag = ldl->ISTag();

            NaughtyFilter checkme(icaphead.HTTPrequest, icaphead.HTTPresponse );
            DataBuffer docbody;
            docbody.setTimeout(o.exchange_timeout);
            docbody.setICAP(true);
            FDTunnel fdt;
            String wline = "";
            if (firsttime) {
                // reset flags & objects next time round the loop
                firsttime = false;
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;
            }

           {
// another round...
#ifndef NEWDEBUG_OFF
                if(o.myDebug->gete2debug())
                {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << " ICAP -persisting (count " << ++pcount << ")" << " Client IP: " << clientip << std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << " ICAP -persisting (count " << ++pcount << ")" << " - " << clientip << std::endl;
                }
#endif
                icaphead.reset();
                if (!icaphead.in(&peerconn, true)) {
                    if (peerconn.isTimedout()) {
#ifndef NEWDEBUG_OFF
                        if(o.myDebug->gete2debug())
                        {
                            std::ostringstream oss (std::ostringstream::out);
                            oss << thread_id << " -ICAP Persistent connection timed out" << std::endl;
                            o.myDebug->Debug("ICAP",oss.str());
                            std::cerr << thread_id << " -ICAP Persistent connection timed out" << std::endl;
                        }
#endif
                        //send error response
                            wline = "ICAP/1.0 408 Request timeout\r\n";
                            wline += "Service: e2guardian 5.0\r\n";
                            wline += "Encapsulated: null-body=0\r\n";
                            wline += "\r\n";
                            peerconn.writeString(wline.toCharArray());
                    } else {

#ifndef NEWDEBUG_OFF
                            if(o.myDebug->gete2debug())
                            {
                                std::ostringstream oss (std::ostringstream::out);
                                oss << thread_id << " -ICAP Persistent connection closed" << std::endl;
                                o.myDebug->Debug("ICAP",oss.str());
                                std::cerr << thread_id << " -ICAP Persistent connection closed" << std::endl;
                            }
#endif
                            // TODO: send error reply if needed
                            break;
                        }
                }
                ++dystat->reqs;

                ip = icaphead.clientip;

                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;

                authed = false;
                isbanneduser = false;

                //requestscanners.clear();
                //responsescanners.clear();

                matchedip = false;
                urlparams.clear();
                postparts.clear();
                checkme.mimetype = "-";
                //exceptionreason = "";
                //exceptioncat = "";
                //room = "";    // CHECK THIS - surely room is persistant?????

                // reset docheader & docbody
                // headers *should* take care of themselves on the next in()
                // actually not entirely true for docheader - we may read
                // certain properties of it (in denyAccess) before we've
                // actually performed the next in(), so make sure we do a full
                // reset now.
                docbody.reset();
                docbody.setICAP(true);
                peerconn.resetChunk();
            }
#ifndef NEWDEBUG_OFF
            if(o.myDebug->gete2debug())
            {
                std::ostringstream oss (std::ostringstream::out);
                oss << thread_id << "service options enabled : " << wline << " icaphead.service_reqmod: "<< icaphead.service_reqmod << " icaphead.service_resmod: " << icaphead.service_resmod << " icaphead.service_options: " << " icaphead.icap_reqmod_service: " << icaphead.icap_reqmod_service << " icaphead.icap_resmod_service: " << icaphead.icap_resmod_service << " icaphead.icap_reqmod_service: " << icaphead.icap_reqmod_service << std::endl;
                o.myDebug->Debug("ICAP",oss.str());
                std::cerr << thread_id << "service options enabled : " << wline << " icaphead.service_reqmod: "<< icaphead.service_reqmod << " icaphead.service_resmod: " << icaphead.service_resmod << " icaphead.service_options: " << " icaphead.icap_reqmod_service: " << icaphead.icap_reqmod_service << " icaphead.icap_resmod_service: " << icaphead.icap_resmod_service << " icaphead.icap_reqmod_service: " << icaphead.icap_reqmod_service << std::endl;
            }
#endif
            // Check service option REQMOD, RESMOD, OPTIONS and call appropreate function(s)
            //
            if (icaphead.service_reqmod && icaphead.icap_reqmod_service) {
#ifndef NEWDEBUG_OFF
                if(o.myDebug->gete2debug())
                {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << "Icap reqmod check " << std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << "Icap reqmod check " << std::endl;
                }
#endif
                if (handleICAPreqmod(peerconn,ip, checkme, icaphead, auth_plugin) == 0){
                    continue;
                }else{
                    break;
                }

            } else if (icaphead.service_resmod && icaphead.icap_resmod_service) {
#ifndef NEWDEBUG_OFF
                if(o.myDebug->gete2debug())
                {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << "Icap resmod check " << std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << "Icap resmod check " << std::endl;
                }
#endif
                if (handleICAPresmod(peerconn,ip, checkme, icaphead, docbody) == 0)
                    continue;
                else
                   break;
            } else if (icaphead.service_options && icaphead.icap_reqmod_service) {
                // respond with option response
                wline = "ICAP/1.0 200 OK\r\n";
                wline += "Methods: REQMOD\r\n";
                wline += "Service: e2guardian 5.0\r\n";
                wline += "ISTag: \"";
                wline += ldl->ISTag();
                wline += "\"\r\n";
                wline += "Encapsulated: null-body=0\r\n";
                wline += "Allow: 204\r\n";
             //   wline += "Preview: 0\r\n";
                wline += "\r\n";
                peerconn.writeString(wline.toCharArray());
#ifndef NEWDEBUG_OFF
                if(o.myDebug->gete2debug())
                {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << "respmod service options response : " << wline << std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << "respmod service options response : " << wline << std::endl;
                }
#endif
            } else if (icaphead.service_options && icaphead.icap_resmod_service) {
               // respond with option response
                wline = "ICAP/1.0 200 OK\r\n";
                wline += "Methods: RESPMOD\r\n";
                wline += "Service: e2guardian 5.0\r\n";
                wline += "ISTag:";
                wline += ldl->ISTag();
                wline += "\r\n";
                wline += "Encapsulated: null-body=0\r\n";
                wline += "Allow: 204\r\n";
             //   wline += "Preview: 0\r\n";
                wline += "\r\n";
                peerconn.writeString(wline.toCharArray());
#ifndef NEWDEBUG_OFF
                if(o.myDebug->gete2debug())
                {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << "respmod service options response : " << wline << std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << "respmod service options response : " << wline << std::endl;
                }
#endif
            } else if ((icaphead.service_reqmod && !icaphead.icap_reqmod_service) ||
                (icaphead.service_resmod && !icaphead.icap_resmod_service)) {
                wline = "ICAP/1.0 405 Method not allowed for service\r\n";
                wline += "Service: e2guardian 5.0\r\n";
                wline += "Encapsulated: null-body=0\r\n";
                wline += "\r\n";
                peerconn.writeString(wline.toCharArray());
#ifndef NEWDEBUG_OFF
                if(o.myDebug->gete2debug())
                {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << "ICAP/1.0 405 Method not allowed for service " << wline << std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << "ICAP/1.0 405 Method not allowed for service " << wline << std::endl;
                }
#endif
           } else {
                //send error response
                wline = "ICAP/1.0 400 Bad request\r\n";
                wline += "Service: e2guardian 5.0\r\n";
                wline += "Encapsulated: null-body=0\r\n";
                wline += "\r\n";
                peerconn.writeString(wline.toCharArray());
#ifndef NEWDEBUG_OFF
                if(o.myDebug->gete2debug())
                {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << "ICAP/1.0 400 Bad request : " << wline << std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << "ICAP/1.0 400 Bad request : " << wline << std::endl;
                }
#endif
            }
        }
    //    } //catch (std::exception & e)

        if (!ismitm)
        try {
#ifndef NEWDEBUG_OFF
            if(o.myDebug->gete2debug())
            {
                std::ostringstream oss (std::ostringstream::out);
                oss << thread_id << "ICAP -Attempting graceful connection close" << std::endl;
                o.myDebug->Debug("ICAP",oss.str());
                std::cerr << thread_id << "ICAP -Attempting graceful connection close" << std::endl;
            }
#endif

            int fd = peerconn.getFD();
            if (fd > -1) {
                if (shutdown(fd, SHUT_WR) == 0) {
                    char buff[2];
                    peerconn.readFromSocket(buff, 2, 0, 5000);
                };
            };

            // close connection to the client
            peerconn.close();
        } catch (std::exception &e) {
#ifndef NEWDEBUG_OFF
        if(o.myDebug->gete2debug())
        {
            std::ostringstream oss (std::ostringstream::out);
            oss << thread_id << " -ICAP connection handler caught an exception on connection closedown: " << e.what() << std::endl;
            o.myDebug->Debug("ICAP",oss.str());
            std::cerr << thread_id << " -ICAP connection handler caught an exception on connection closedown: " << e.what() << std::endl;
        }
#endif
            // close connection to the client
            peerconn.close();
        }

    return 0;
}


int ConnectionHandler::handleICAPreqmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead,
                                        AuthPlugin *auth_plugin) {
    bool authed = false;
    String clientip = ip;
    // do all of this normalisation etc just the once at the start.
    checkme.setURL();
    String res_hdr, res_body, req_hdr, req_body;

    // checks for bad URLs to prevent security holes/domain obfuscation.
    if (icaphead.HTTPrequest.malformedURL(checkme.url)) {
        // The requested URL is malformed.
        gen_error_mess(peerconn, checkme, res_hdr, res_body, 200, 0, "400 Bad Request");
        checkme.isdone = true;
        icaphead.errorResponse(peerconn, res_hdr, res_body);
        if (icaphead.req_body_flag) {
            peerconn.drainChunk(peerconn.getTimeout());   // drains body
        }
        return 0;
    }

    // do total block list checking here - now done in pre-auth story
#ifdef NOTDEF
    if (o.use_total_block_list && o.inTotalBlockList(checkme.urld)) {
        res_hdr = "HTTP/1.1 200 OK\n";
        o.banned_image.display_hb(res_hdr, res_body);
        icaphead.errorResponse(peerconn, res_hdr, res_body);
        if (icaphead.req_body_flag) {
            peerconn.drainChunk(peerconn.getTimeout());   // drains body
        }
        return 0;
    }
#endif

    //
    //
    // Start of Authentication Checks
    //
    //
    // don't have credentials for this connection yet? get some!
    overide_persist = false;
    filtergroup = o.default_icap_fg;
#ifdef DGBEBUG
    std::cerr << thread_id << "filtergroup set to ICAP default " << filtergroup << " " < std::endl;
#endif
    clientuser = icaphead.username;
    int rc = DGAUTH_NOUSER;
    if(clientuser != "") {
        rc = determineGroup(clientuser, filtergroup, ldl->filter_groups_list);
    }
    //if (rc != DGAUTH_OK)
    else {                              // TODO - NEED to allow alternate group checking when no match in filter_groups_list
            if (!doAuth(authed, filtergroup, auth_plugin, peerconn, icaphead.HTTPrequest, true)) {
                //break;  // TODO Error return????
            }
    }

    authed = true;
    checkme.filtergroup = filtergroup;

#ifndef NEWDEBUG_OFF
    if(o.myDebug->gete2debug())
    {
            std::ostringstream oss (std::ostringstream::out);
            int unrealgroup = filtergroup+1;
            oss << thread_id << "-username: " << clientuser << " ICAP -filtergroup: " << unrealgroup  << std::endl;
            o.myDebug->Debug("ICAP",oss.str());
            std::cerr << thread_id << "-username: " << clientuser << " ICAP -filtergroup: " << unrealgroup  << std::endl;
    }
#endif

//
//
// End of Authentication Checking
//
//


    //
    //
    // Now check if user or machine is banned and room-based checking
    //
    //

    // is this user banned?
    bool isbanneduser = false;
    checkme.clientip = clientip;

    // Look up reverse DNS name of client if needed
    if (o.reverse_client_ip_lookups) {
        std::unique_ptr<std::deque<String> > hostnames;
            hostnames.reset(ipToHostname(clientip.c_str()));
            checkme.clienthost = std::string(hostnames->front().toCharArray());
    }

    //CALL SB pre-authcheck
    ldl->StoryA.runFunctEntry(ENT_STORYA_PRE_AUTH_ICAP, checkme);
#ifdef DGDEBUG
    std::cerr << thread_id << "After StoryA icap-pre-authcheck" << checkme.isexception << " mess_no "
              << checkme.message_no << std::endl;
#endif
    checkme.isItNaughty = checkme.isBlocked;
    bool isbannedip = checkme.isBlocked;
    bool part_banned;
    if (isbannedip) {
        // matchedip = clienthost == NULL;
    } else {
#ifdef NOTDEF      // TODO does this need restoring???
        if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
                        checkme.urld)) {
#ifdef DGDEBUG
            std::cerr << thread_id << "ICAP isbannedip = " << isbannedip << "ispart_banned = " << part_banned << " isexception = " << checkme.isexception << std::endl;
#endif
            if (isbannedip) {
         //       matchedip = clienthost == NULL;
                checkme.isBlocked = checkme.isItNaughty = true;
            }
            if (checkme.isexception) {
                // do reason codes etc
                checkme.exceptionreason = o.language_list.getTranslation(630);
                checkme.exceptionreason.append(room);
                checkme.exceptionreason.append(o.language_list.getTranslation(631));
                checkme.message_no = 632;
            }
        }
#endif
    }

    //
    // Start of by pass
    if(!checkme.is_ssl) {

        if (checkByPass(checkme, ldl, icaphead.HTTPrequest, peerconn, peerconn, clientip)
            && sendScanFile(peerconn, checkme, true, &icaphead)) {
            return 0;      // returns only when Scanfile sent. Sets checkme.isbypass if it is a bypass.
        }
    }
    //
    // End of scan by pass
    //

    char *retchar;
    bool done = false;

    //
    // Start of exception checking
    //
    // being a banned user/IP overrides the fact that a site may be in the exception lists
    // needn't check these lists in bypass modes
    if (!(isbanneduser || isbannedip ||  checkme.isexception)) {
// Main checking is now done in Storyboard function(s)
        ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_ICAP_REQMOD, checkme);
#ifdef DGDEBUG
        std::cerr << thread_id << "After StoryB checkreqmod" << checkme.isexception << " mess_no "
                  << checkme.message_no << " allow_204 : " << icaphead.allow_204 << std::endl;
#endif
        checkme.isItNaughty = checkme.isBlocked;
    }

    if (checkme.isbypass && !(checkme.iscookiebypass || checkme.isvirusbypass)) {
#ifdef DGDEBUG
        std::cout << thread_id << "Setting GBYPASS cookie; bypasstimestamp = " << checkme.bypasstimestamp << __func__ << std::endl;
#endif
        String ud(checkme.urldomain);
        if (ud.startsWith("www.")) {
            ud = ud.after("www.");
        }
        // redirect user to URL with GBYPASS parameter no longer appended
        String outhead = "HTTP/1.1 302 Redirect\r\n";
        outhead += "Set-Cookie: GBYPASS=";
        outhead += hashedCookie(&ud, ldl->fg[filtergroup]->cookie_magic.c_str(),&clientip,
                                checkme.bypasstimestamp).toCharArray();
        outhead += "; path=/; domain=.";
        outhead += ud;
        outhead += "\r\n";
        outhead += "Location: ";
        outhead += icaphead.HTTPrequest.getUrl(true);
        outhead += "\r\n";
        outhead += "\r\n";
        icaphead.out_res_header = outhead;
        icaphead.out_res_hdr_flag = true;
        icaphead.respond(peerconn);
        return 0;
    }

// TODO add logicv for 204 response etc.
    if (checkme.isexception) {
        std::string code;
        if (checkme.isvirusbypass)
            code = "V";
        else if (checkme.isbypass)
            code = "Y";
        else
            code = "E";

        icaphead.set_icap_com(clientuser,code, filtergroup, checkme.message_no, checkme.log_message_no,
        checkme.whatIsNaughtyLog);
        if (icaphead.allow_204) {
            icaphead.respond(peerconn, "204 No Content");
            if (icaphead.req_body_flag) {
                peerconn.drainChunk(peerconn.getTimeout());   // drains any body
            }
            done = true;
        } else {
            // pipe through headers and body
            icaphead.respond(peerconn, "200 OK", true);
            if (icaphead.req_body_flag) {
                peerconn.loopChunk(peerconn.getTimeout());   // echos any body
            }
            done = true;
        }
    }

    //check for redirect
    // URL regexp search and edirect
    if (checkme.urlredirect) {
        checkme.url = icaphead.HTTPrequest.redirecturl();
        String writestring("HTTP/1.1 302 Redirect\r\nLocation: ");
        writestring += checkme.url;
        writestring += "\r\n\r\n";
        res_hdr = writestring;
        icaphead.errorResponse(peerconn, res_hdr, res_body);
        if (icaphead.req_body_flag) {
            peerconn.drainChunk(peerconn.getTimeout());   // drains any body
        }
        done = true;
    }

    //if  is a search - content check search terms
    if (!done && checkme.isSearch)
        check_search_terms(checkme);  // will set isItNaughty if needed


    // TODO V5 call POST scanning code New NaughtyFilter function????

    if (checkme.isItNaughty) {
        if (genDenyAccess(peerconn, res_hdr, res_body, &icaphead.HTTPrequest, &icaphead.HTTPresponse,
                          &checkme.url, &checkme, &clientuser, &clientip,
                          filtergroup, checkme.ispostblock, checkme.headersent, checkme.wasinfected,
                          checkme.scanerror)) {
            icaphead.errorResponse(peerconn, res_hdr, res_body);
            if (icaphead.req_body_flag) {
                peerconn.drainChunk(peerconn.getTimeout());   // drains any body
            }
            done = true;
#ifdef DGDEBUG
            std::cerr << thread_id << "ICAP Naughty" << std::endl;
#endif
	// break loop "// maintain a persistent connection"
   	  // return 1;
        };
    }


    if (!done) {
        icaphead.set_icap_com(clientuser, "G", filtergroup,checkme.message_no,checkme.log_message_no,
        checkme.whatIsNaughtyLog);
        icaphead.respond(peerconn, "200 OK", true);
        if (icaphead.req_body_flag) {
            peerconn.loopChunk(peerconn.getTimeout());   // echoes any body
        }
    }
    //Log
    if (!(checkme.isourwebserver || checkme.nolog))  { // don't log requests to the web server
        doLog(clientuser, clientip, checkme);
    }
    return 0;
}

int ConnectionHandler::handleICAPresmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead, DataBuffer &docbody) {

    bool authed = false;
    bool persistPeer = true;
    bool done = false;
    String clientip = ip;
    String res_hdr, res_body;
    std::deque<CSPlugin *> responsescanners;

            // do all of this normalisation etc just the once at the start.
    checkme.setURL();

    overide_persist = false;
    if(icaphead.icap_com.filtergroup < 0)    //i.e. no X-ICAP-E2G
    {
        String wline = "ICAP/1.0 418 Bad composition - X-ICAP-E2G header not present\r\n";
        wline += "Service: e2guardian 5.0\r\n";
        wline += "Encapsulated: null-body=0\r\n";
        wline += "\r\n";
        peerconn.writeString(wline.toCharArray());
#ifndef NEWDEBUG_OFF
        if(o.myDebug->gete2debug())
        {
                std::ostringstream oss (std::ostringstream::out);
                oss << thread_id << " ICAP Error: " << wline << std::endl;
                o.myDebug->Debug("ICAP",oss.str());
                std::cerr << thread_id << " ICAP Error: " << wline << std::endl;
        }
#endif
        return 1;
    }

    filtergroup = icaphead.icap_com.filtergroup;
    clientuser = icaphead.icap_com.user;
    if (icaphead.icap_com.EBG == "E") {    // exception
        checkme.isexception = true;
        checkme.message_no = icaphead.icap_com.mess_no;
        checkme.log_message_no = icaphead.icap_com.log_mess_no;
        checkme.whatIsNaughtyLog = icaphead.icap_com.mess_string;
    } else if (icaphead.icap_com.EBG == "G")     // grey - content check
        checkme.isGrey = true;
    else if (icaphead.icap_com.EBG == "Y") {   // ordinary bypass
        checkme.isbypass = true;
        checkme.isexception = true;
        checkme.message_no = icaphead.icap_com.mess_no;
        checkme.log_message_no = icaphead.icap_com.log_mess_no;
        checkme.whatIsNaughtyLog = icaphead.icap_com.mess_string;
    } else if (icaphead.icap_com.EBG == "V") {   // virus bypass
        checkme.isvirusbypass = true;
        checkme.isbypass = true;
        checkme.isexception = true;
        checkme.message_no = icaphead.icap_com.mess_no;
        checkme.log_message_no = icaphead.icap_com.log_mess_no;
        checkme.whatIsNaughtyLog = icaphead.icap_com.mess_string;
    }

#ifndef NEWDEBUG_OFF
    if(o.myDebug->gete2debug())
    {
            int unrealfiltergroup = filtergroup + 1;
            std::ostringstream oss (std::ostringstream::out);
            oss << thread_id << "ICAP Respmod enabled - username: " << clientuser << " -filtergroup: " << unrealfiltergroup << " icaphead.icap_com.EBG: " << icaphead.icap_com.EBG << " icaphead.res_body_flag: " << icaphead.res_body_flag << std::endl;
            o.myDebug->Debug("ICAP",oss.str());
            std::cerr << thread_id << "ICAP Respmod enabled -username: " << clientuser << " -filtergroup: " << unrealfiltergroup << " icaphead.icap_com.EBG: " << icaphead.icap_com.EBG << " icaphead.res_body_flag: " << icaphead.res_body_flag  << std::endl;
    }
#endif

    checkme.clientip = ip;
    checkme.filtergroup = filtergroup;
    // Look up reverse DNS name of client if needed
    if (o.reverse_client_ip_lookups) {
        std::unique_ptr<std::deque<String> > hostnames;
            hostnames.reset(ipToHostname(checkme.clientip.c_str()));
            checkme.clienthost = std::string(hostnames->front().toCharArray());
    }

    bool part_banned;
    char *retchar;

    // virus checkichurchillng candidate?
    // checkme.noviruscheck defaults to true
#ifndef NEWDEBUG_OFF
    if(o.myDebug->gete2debug())
        {
                std::ostringstream oss (std::ostringstream::out);
                oss << thread_id << "Virus scan checkme.isexception: " << checkme.isexception  << " checkme.noviruscheck: " << checkme.noviruscheck << " content_scan_exceptions: " << ldl->fg[filtergroup]->content_scan_exceptions << " checkme.isBlocked: " << checkme.isBlocked << " disable_content_scan: " << ldl->fg[filtergroup]->disable_content_scan << " csplugins: " << o.csplugins.size() << std::endl;
                o.myDebug->Debug("ICAP",oss.str());
                std::cerr << thread_id << "Virus scan checkme.isexception: " << checkme.isexception  << " checkme.noviruscheck: " << checkme.noviruscheck << " content_scan_exceptions: " << ldl->fg[filtergroup]->content_scan_exceptions << " checkme.isBlocked: " << checkme.isBlocked << " disable_content_scan: " << ldl->fg[filtergroup]->disable_content_scan << " csplugins: " << o.csplugins.size() << std::endl;
            }
#endif

    if (icaphead.res_body_flag    //  can only  scan if  body present
        && !(checkme.isBlocked)  // or not already blocked
        && (o.csplugins.size() > 0)            //  and we have scan plugins
        && !ldl->fg[filtergroup]->disable_content_scan    // and is not disabled
        && !(checkme.isexception && !ldl->fg[filtergroup]->content_scan_exceptions)
        && !checkme.isvirusbypass   // and is not virus bypass
        // and not exception unless scan exceptions enable
        ) {
        checkme.noviruscheck = false;   // note this may be reset by Storyboard to enable exceptions
    }

            //
            // being a banned user/IP overrides the fact that a site may be in the exception lists
            // needn't check these lists in bypass modes
    if (!(checkme.isexception) || !checkme.noviruscheck) {
// Main checking is done in Storyboard function(s)
            ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_ICAP_RESMOD,checkme);
#ifndef NEWDEBUG_OFF
            if(o.myDebug->gete2debug())
            {
                    std::ostringstream oss (std::ostringstream::out);
                    oss << thread_id << "After StoryB icapcheckresmod" << checkme.isexception << " mess_no " << checkme.message_no  << " checkme.noviruscheck: "<< checkme.noviruscheck << " content_scan_exceptions: " << ldl->fg[filtergroup]->content_scan_exceptions <<  std::endl;
                    o.myDebug->Debug("ICAP",oss.str());
                    std::cerr << thread_id << "After StoryB icapcheckresmod" << checkme.isexception << " mess_no " << checkme.message_no  << " checkme.noviruscheck: "<< checkme.noviruscheck << " content_scan_exceptions: " << ldl->fg[filtergroup]->content_scan_exceptions << std::endl;
            }
#endif
            checkme.isItNaughty = checkme.isBlocked;
    }

    if(checkme.isexception &&!checkme.noviruscheck && !ldl->fg[filtergroup]->content_scan_exceptions)
        checkme.noviruscheck = true;

    if (ldl->fg[filtergroup]->content_scan_exceptions && checkme.isexception)
        checkme.noviruscheck = false;

    if ((checkme.isexception && checkme.noviruscheck)|| !icaphead.res_body_flag) {
        if (icaphead.allow_204) {
            icaphead.respond(peerconn, "204 No Content");
            if (icaphead.res_body_flag) {
                peerconn.drainChunk(peerconn.getTimeout());   // drains any body
            }
        } else {
            // pipe through headers and body
            icaphead.respond(peerconn, "200 OK", true);
            if (icaphead.res_body_flag) {
                peerconn.loopChunk(peerconn.getTimeout());   // echos any body
            }
        }
        done = true;
    }

    // should now only be left with grey which has content body

            //- if grey content check
                // can't do content filtering on HEAD or redirections (no content)
                // actually, redirections CAN have content

   if (!done && !checkme.isItNaughty) {
           if(!checkme.noviruscheck)
                {
                    for (std::deque<Plugin *>::iterator i = o.csplugins_begin; i != o.csplugins_end; ++i) {
                        int csrc = ((CSPlugin *)(*i))->willScanRequest(checkme.url, clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(), false, false, checkme.isexception, checkme.isbypass);
                        if (csrc > 0)
                            responsescanners.push_back((CSPlugin *)(*i));
                        else if (csrc < 0)
                            syslog(LOG_ERR, "%swillScanRequest returned error: %d", thread_id.c_str(), csrc);
                    }
                }
                check_content(checkme, docbody,peerconn, peerconn,responsescanners);
    }

    //send response header to client
    if(!checkme.isItNaughty)  {
        icaphead.respond(peerconn, "200 OK", true);
        if(checkme.waschecked) {
            if (!docbody.out(&peerconn))
                checkme.pausedtoobig = false;
            if (checkme.pausedtoobig)
                checkme.tunnel_rest = true;
        }
        if (checkme.tunnel_rest)
            peerconn.loopChunk(peerconn.getTimeout());   // echos any body
            done = true;
    }


    if(checkme.isItNaughty) {
        if(genDenyAccess(peerconn,res_hdr, res_body, &icaphead.HTTPrequest, &icaphead.HTTPresponse, &checkme.url, &checkme, &clientuser, &ip,
                filtergroup, checkme.ispostblock,checkme.headersent, checkme.wasinfected, checkme.scanerror))
        {
            icaphead.errorResponse(peerconn, res_hdr, res_body);
            if (icaphead.res_body_flag) {
                peerconn.drainChunk(peerconn.getTimeout());   // drains any body
            }
            done = true;
        }
            persistPeer = false;
        }

            //Log
    if (!checkme.isourwebserver && checkme.isItNaughty) { // don't log requests to the web server & and normal response
        checkme.whatIsNaughtyLog = "ICAP Response filtering: ";
        checkme.whatIsNaughtyLog += checkme.whatIsNaughty;
        doLog(clientuser, clientip, checkme);
    }
    if (persistPeer)
        return 0;
    else
        return 1;
}

// determine what filter group the given username is in
// return -1 when user not found
int ConnectionHandler::determineGroup(std::string &user, int &fg, ListContainer & uglc)
{
    if (user.length() < 1 || user == "-") {
        return DGAUTH_NOMATCH;
    }
    String u(user);
    String lastcategory;
    u.toLower(); // since the filtergroupslist is read in in lowercase, we should do this.
    user = u.toCharArray(); // also pass back to ConnectionHandler, so appears lowercase in logs
    String ue(u);
    ue += "=";

    //char *i = ldl->filter_groups_list.findStartsWithPartial(ue.toCharArray(), lastcategory);
    char *i = uglc.findStartsWithPartial(ue.toCharArray(), lastcategory);

    if (i == NULL) {
#ifdef DGDEBUG
        std::cerr << thread_id << "User not in filter groups list: " << ue << std::endl;
#endif
        return DGAUTH_NOUSER;
    }
#ifdef DGDEBUG
    std::cerr << thread_id << "User found in filter group list: " << i << std::endl;
#endif
    ue = i;
    if (ue.before("=") == u) {
        ue = ue.after("=filter");
        int l = ue.length();
        if (l < 1 || l > 2) {
            return DGAUTH_NOUSER;
        }
        int t;
        t = ue.toInteger();
        if (t > o.numfg) {
            return DGAUTH_NOUSER;
        }
        if (t > 0 ) {
            fg = --t;
#ifdef DGDEBUG
            std::cerr << thread_id << "determineGroup gives fg:  " << fg << std::endl;
#endif
            return DGAUTH_OK;
        }
    }
    return DGAUTH_NOUSER;
}


