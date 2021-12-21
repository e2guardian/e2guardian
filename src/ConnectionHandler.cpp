// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
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
#include "Logger.hpp"

#include <signal.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "CertificateAuthority.hpp"

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

#include "openssl/ssl.h"
#include "openssl/x509v3.h"
#include "String.hpp"

// GLOBALS
extern OptionContainer o;
extern std::atomic<bool> ttg;

// IMPLEMENTATION

ConnectionHandler::ConnectionHandler()
        : clienthost(NULL) {

    // initialise SBauth structure
    SBauth.filter_group = 0;
    SBauth.is_authed = false;
    SBauth.user_name = "";
}


// Custom exception class for POST filtering errors
class postfilter_exception : public std::runtime_error {
public:
    postfilter_exception(const char *const &msg)
            : std::runtime_error(msg) {};
};

//
// URL cache funcs
//

// check the URL cache to see if we've already flagged an address as clean
bool wasClean(HTTPHeader &header, String &url, const int fg) {
    return false;   // this function needs rewriting always return false
}

// add a known clean URL to the cache
void addToClean(String &url, const int fg) {
    return;   // this function needs rewriting
}

//
// ConnectionHandler class
//

void ConnectionHandler::peerDiag(const char *message, Socket &peersock) {
    if (o.conn.logconerror) {
        //int peerport = peersock.getPeerSourcePort();
        std::string peer_ip = peersock.getPeerIP();
        int err = peersock.getErrno();

        if (peersock.isTimedout()) {
            E2LOGGER_info(message, " Client at ", peer_ip, " Connection timedout - errno: ", err);
        } else if (peersock.isHup()) {
            E2LOGGER_info(message, " Client at ", peer_ip, " has disconnected - errno: ", err);
        } else if (peersock.sockError()) {
                E2LOGGER_info(message, " Client at ", peer_ip, " Connection socket error - errno: ", err);
        } else if (peersock.isNoRead()) {
                E2LOGGER_info(message, " cant read Client Connection at ", peer_ip, " - errno: ", err);
        } else if (peersock.isNoWrite()) {
                E2LOGGER_info(message, " cant write Client Connection at ", peer_ip, " - errno: ", err);
        } else if (peersock.isNoOpp()) {
                E2LOGGER_info(message, " Client Connection is no-op - errno: ", err);
        } else {
                E2LOGGER_info(message, " Client Connection at ", peer_ip, " problem - errno: ", err);
        }
}
}

void ConnectionHandler::upstreamDiag(const char *message, Socket &proxysock) {
    if (o.conn.logconerror) {

        int err = proxysock.getErrno();
        if (proxysock.isTimedout()) {
            E2LOGGER_info(message, " upstream timedout - errno: ", err);
        } else if (proxysock.isHup()) {
            E2LOGGER_info(message, " upstream has disconnected - errno: ", err);
        } else if (proxysock.sockError())  {
            E2LOGGER_info(message, " upstream socket error - errno: ", err);
        } else if (proxysock.isNoRead()) {
            E2LOGGER_info(message, " cant read upstream Connection - errno: ", err);
        } else if (proxysock.isNoWrite()) {
            E2LOGGER_info(message, " cant write upstream Connection  - errno: ", err);
        } else if (proxysock.isNoOpp()) {
            E2LOGGER_info(message, " upstream Connection is no-op - errno: ", err);
        } else {
            E2LOGGER_info(message, " upstream Connection problem - errno: ", err);
        }
    }
    if (proxysock.isNoOpp())
        proxysock.close();
}


// perform URL encoding on a string
std::string ConnectionHandler::miniURLEncode(const char *s) {
    std::string encoded;
    char *buf = new char[3];
    unsigned char c;
    for (int i = 0; i < (signed) strlen(s); i++) {
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
String ConnectionHandler::hashedURL(String *url, int filtergroup, std::string *clientip,
                                    bool infectionbypass, std::string *user) {
    // filter/virus bypass hashes last for a certain time only
    String timecode(time(NULL) + (infectionbypass ? (*ldl->fg[filtergroup]).infection_bypass_mode
                                                  : (*ldl->fg[filtergroup]).bypass_mode));
    // use the standard key in normal bypass mode, and the infection key in infection bypass mode
    String magic(infectionbypass ? ldl->fg[filtergroup]->imagic.c_str() : ldl->fg[filtergroup]->magic.c_str());
    magic += clientip->c_str();
    if(ldl->fg[filtergroup]->bypass_v2)
        magic += user->c_str();
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
    DEBUG_debug(" -generate Bypass hashedurl data ", clientip, " ", *url, " ", clientuser, " ", timecode, " result ", res);
    return res;
}

// create temporary bypass cookie
String ConnectionHandler::hashedCookie(String *url, const char *magic, std::string *clientip, int bypasstimestamp) {
    String timecode(bypasstimestamp);
    String data(magic);
    data += clientip->c_str();
    data += clientuser;
    data += timecode;
    DEBUG_debug(" -generate Bypass hashedCookie data ", clientip, " ", *url, " ", clientuser, " ", timecode);
    String res(url->md5(data.toCharArray()));
    res += timecode;
    DEBUG_debug(" -Bypass hashedCookie="+ res);
    return res;
}


// is this a temporary filter bypass URL?
int ConnectionHandler::isBypassURL(String url, const char *magic, const char *clientip, std::string btype, std::string &user)
{
    //if ((url).length() <= 45)
    //    return 0; // Too short, can't be a bypass

    // check to see if this is a bypass URL of the btype type
    if(!(url).contains(btype.c_str()))
        return 0;

    DEBUG_debug("URL ", btype, " found checking...");

    String url_left((url).before(btype.c_str()));
    url_left.chop(); // remove the ? or &
    String url_right((url).after(btype.c_str()));
    String url_hash(url_right.subString(0, 32));
    String url_time(url_right.after(url_hash.toCharArray()));
    DEBUG_debug("URL: ", url_left, ", HASH: ", url_hash, ", TIME: ", url_time);

    String mymagic(magic);
    mymagic += clientip;
    if(ldl->fg[filtergroup]->bypass_v2)
        mymagic += user;
    mymagic += url_time;
    String hashed(url_left.md5(mymagic.toCharArray()));

    if(ldl->fg[filtergroup]->cgi_bypass_v2) {
        mymagic = hashed;
        hashed = mymagic.md5(ldl->fg[filtergroup]->cgi_magic.c_str());
    }

    if (hashed != url_hash) {
        DEBUG_debug("URL ", btype, " hash mismatch");
        return 0;
    }

    time_t timen = time(NULL);
    time_t timeu = url_time.toLong();

    if (timeu < 1) {
        DEBUG_debug("URL ", btype, " bad time value");
        return 1; // bad time value
    }
    if (timeu < timen) { // expired key
        DEBUG_debug("URL ", btype, " expired");
        return 1; // denotes expired but there
    }
    DEBUG_debug("URL ", btype, " not expired");
    return (int)timeu;
}

// is this a scan bypass URL? i.e. a "magic" URL for retrieving a previously scanned file
bool ConnectionHandler::isScanBypassURL(String url, const char *magic, const char *clientip)
{
   // if ((url).length() <= 45)
   //     return false; // Too short, can't be a bypass

    if (!(url).contains("GSBYPASS=")) { // If this is not a bypass url
        return false;
    }
    DEBUG_debug("URL GSBYPASS found checking...");

    String url_left((url).before("GSBYPASS="));
    url_left.chop(); // remove the ? or &
    String url_right((url).after("GSBYPASS="));

    String url_hash(url_right.subString(0, 32));
    DEBUG_debug("URL: ", url_left, ", HASH: ", url_hash);

    // format is:
    // GSBYPASS=hash(ip+url+tempfilename+mime+disposition+secret)
    // &N=tempfilename&M=mimetype&D=dispos

    String tempfilename(url_right.after("&N="));
    String tempfilemime(tempfilename.after("&M="));
    String tempfiledis(tempfilemime.after("&D="));
    tempfilemime = tempfilemime.before("&D=");
    tempfilename = tempfilename.before("&M=");

    String tohash(clientip + url_left + tempfilename + tempfilemime + tempfiledis + magic);
    String hashed(tohash.md5());

    if(ldl->fg[filtergroup]->cgi_bypass_v2) {
        tohash = hashed;
        hashed = tohash.md5(ldl->fg[filtergroup]->cgi_magic.c_str());
    }

    DEBUG_debug("checking hash: ", clientip, " ", url_left, " ", tempfilename, " ",
                    tempfilemime, " ", tempfiledis, " ", magic, " ", hashed);

    if (hashed == url_hash) {
        return true;
    }
    DEBUG_debug("URL GSBYPASS HASH mismatch");

    return false;
}

// send a file to the client - used during bypass of blocked downloads
off_t
ConnectionHandler::sendFile(Socket *peerconn, NaughtyFilter &cm, String &url, bool is_icap, ICAPHeader *icap_head) {
    String filedis = cm.tempfiledis;
    int fd = open(cm.tempfilename.toCharArray(), O_RDONLY);
    if (fd < 0) { // file access error
        E2LOGGER_error("Error reading file to send: ", cm.tempfilename);

        String fnf(o.language_list.getTranslation(1230));
        String head("HTTP/1.1 404 " + fnf + "\r\nContent-Type: text/html\r\n\r\n");
        String body("<HTML><HEAD><TITLE>" + fnf + "</TITLE></HEAD><BODY><H1>" + fnf + "</H1></BODY></HTML>\r\n");

        if (is_icap) {
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
        rc = read(fd, buffer, 64000);
        DEBUG_debug(" -reading send file rc:", String(rc));
        if (rc < 0) {
            E2LOGGER_error(" -error reading send file so aborting");
            delete[] buffer;
//            throw std::exception/();
            //cleanThrow("error reading send file", *peerconn);
            return 0;
        }
        if (rc == 0) {
            E2LOGGER_error(" -got zero bytes reading send file");
            break; // should never happen
        }
        if (is_icap) {
            if (!peerconn->writeChunk(buffer, rc, 100000)) {
                delete[] buffer;
                peerDiag("Error sending file to client", *peerconn);
                return 0;
            }
        } else {
            // as it's cached to disk the buffer must be reasonably big
            if (!peerconn->writeToSocket(buffer, rc, 0, 100000)) {
                delete[] buffer;
                peerDiag("Error sending file to client", *peerconn);
                return 0;
                // throw std::exception();
            }
        }
        sent += rc;
        DEBUG_debug(" -total sent from temp: ", String(sent));

    }
    if (is_icap) {
        String n;
        peerconn->writeChunkTrailer(n);
    }
    delete[] buffer;
    close(fd);
    return sent;
}

int
ConnectionHandler::connectUpstream(Socket &sock, NaughtyFilter &cm, int port = 0)   // connects to to proxy or directly
{
    if (port == 0)
        port = cm.request_header->port;
    String sport(port);
    int lerr_mess = 0;
    int retry = -1;
    bool may_be_loop = false;
    for (auto it = o.net.check_ports.begin(); it != o.net.check_ports.end(); it++) {
        if (*it == sport) {
            may_be_loop = true;
            break;
        }
    }
    DEBUG_debug("May_be_loop = ", may_be_loop, " ", " port ", port);

    sock.setTimeout(o.net.connect_timeout);

    while (++retry < o.net.connect_retries) {
        lerr_mess = 0;
        if (retry > 0) {
            if (o.conn.logconerror)
                E2LOGGER_info("retry ", retry, " to connect to ", cm.urldomain);
            if (!sock.isTimedout())
                usleep(1000);       // don't hammer upstream
        }
        cm.upfailure = false;
        if (cm.isdirect) {
            String des_ip;
            if (cm.isiphost)
                des_ip = cm.urldomain;
            if(o.conn.use_original_ip_port && cm.got_orig_ip && (cm.connect_site == cm.urldomain))
                des_ip = cm.orig_ip;

            if(des_ip.length() > 0) {
                if (may_be_loop) {  // check check_ip list
                    bool do_break = false;
                    if (o.net.check_ip.size() > 0) {
                        for (auto it = o.net.check_ip.begin(); it != o.net.check_ip.end(); it++) {
                            if (*it == des_ip) {
                                do_break = true;
                                lerr_mess = 212;
                                break;
                            }
                        }
                    }
                    if (do_break) break;
                    may_be_loop = false;
                }


                DEBUG_debug("Connecting to IP ", des_ip, " port ", String(port));

                int rc = sock.connect(des_ip, port);
                if (rc < 0) {
                    lerr_mess = 203;
                    continue;
                }
                return rc;
            } else {
                //dns lookup
                struct addrinfo hints, *infoptr;
                memset(&hints, 0, sizeof(addrinfo));
                hints.ai_family = AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags = 0;
                hints.ai_protocol = 0;
                hints.ai_canonname = NULL;
                hints.ai_addr = NULL;
                hints.ai_next = NULL;
                int rc = getaddrinfo(cm.connect_site.toCharArray(), NULL, &hints, &infoptr);
                if (rc)  // problem
                {
                    DEBUG_debug("connectUpstream: getaddrinfo returned ", String(rc),
                                " for ", cm.connect_site, " ", gai_strerror(rc) );

                    bool rt = false;
                    switch (rc) {
                        case EAI_NONAME:
                            lerr_mess = 207;
                            break;
#ifdef EAI_NODATA
                        case EAI_NODATA:
                            lerr_mess = 208;
                            break;
#endif
                        case EAI_AGAIN:
                            lerr_mess = 209;
                            rt = true;
                            break;
                        case EAI_FAIL:
                            lerr_mess = 210;
                            break;
                        default:
                            lerr_mess = 210;  //TODO this should have it's own message??
                            break;
                    }
                    sock.close();
                    if (rt) continue;
                    else break;
                }
                char t[256];
                struct addrinfo *p;
                for (p = infoptr; p != NULL; p = p->ai_next) {
                    getnameinfo(p->ai_addr, p->ai_addrlen, t, sizeof(t), NULL, 0, NI_NUMERICHOST);
                    if (may_be_loop) {  // check check_ip list
                        bool do_break = false;
                        if (o.net.check_ip.size() > 0) {
                            for (auto it = o.net.check_ip.begin(); it != o.net.check_ip.end(); it++) {
                                if (*it == t) {
                                    do_break = true;
                                    lerr_mess = 212;
                                    break;
                                }
                            }
                        }
                        if (do_break) break;
                        may_be_loop = false;
                    }

                    DEBUG_debug("Connecting to IP ", t, " port ", String(port));
                    int rc = sock.connect(t, port);
                    if (rc == 0) {
                        freeaddrinfo(infoptr);
                        DEBUG_debug("Got connection upfailure is ", String(cm.upfailure) );
                        return 0;
                    }
                }
                freeaddrinfo(infoptr);
                if (may_be_loop) break;
                lerr_mess = 203;
                continue;
            }
        } else {  //is via proxy
            sock.setTimeout(o.net.proxy_timeout);
            int rc = sock.connect(o.net.proxy_ip, o.net.proxy_port);
            if (rc < 0) {
                if (sock.isTimedout())
                    lerr_mess = 201;
                else
                    lerr_mess = 202;
                continue;
            }
            return rc;
        }
    }

    // only get here if failed
    cm.upfailure = true;
    cm.message_no = lerr_mess;
    cm.whatIsNaughty = o.language_list.getTranslation(lerr_mess);
    cm.whatIsNaughtyLog = cm.whatIsNaughty;
    cm.whatIsNaughtyCategories = "";
    cm.whatIsNaughtyDisplayCategories = "";
    cm.isItNaughty = true;
    cm.blocktype = 3;
    cm.isexception = false;
    cm.isbypass = false;
    return -1;
}

// pass data between proxy and client, filtering as we go.
// this is the only public function of ConnectionHandler
int ConnectionHandler::handlePeer(Socket &peerconn, String &ip, stat_rec *&dystat, unsigned int lc_type) {
    persistent_authed = false;
    is_real_user = false;
    int rc = 0;
    Socket proxysock;    // also used for direct connection

    switch (lc_type) {
        case CT_PROXY:
            SBauth.is_proxy = true;
            rc = handleConnection(peerconn, ip, false, proxysock, dystat);
            break;

        case  CT_THTTPS:
            SBauth.is_transparent = true;
            rc = handleTHTTPSConnection(peerconn, ip, proxysock, dystat);
            break;

        case  CT_PROXY_TLS:
            SBauth.is_proxy = true;
            rc = handleProxyTLSConnection(peerconn, ip, proxysock, dystat);
            break;

        case CT_ICAP:
            SBauth.is_icap = true;
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
    peerconn.setTimeout(o.net.pcon_timeout);
    DEBUG_proxy("down_stream thread ",peerconn.down_thread_id);

    // ldl = o.currentLists();

    HTTPHeader docheader(__HEADER_RESPONSE); // to hold the returned page header from proxy
    HTTPHeader header(__HEADER_REQUEST); // to hold the incoming client request headeri(ldl)

    // set a timeout as we don't want blocking 4 eva
    // this also sets how long a peerconn will wait for other requests
    header.setTimeout(o.net.pcon_timeout);
    docheader.setTimeout(o.net.exchange_timeout);


    //int bypasstimestamp = 0;


    // Content scanning plugins to use for request (POST) & response data
    std::deque<CSPlugin *> requestscanners;
    std::deque<CSPlugin *> responsescanners;

    std::string clientip(ip.toCharArray()); // hold the clients ip
    header.setClientIP(ip);

    if (clienthost) delete clienthost;

    clienthost = NULL; // and the hostname, if available
    matchedip = false;

    // clear list of parameters extracted from URL
    urlparams.clear();

    // clear out info about POST data
    postparts.clear();

    // debug stuff surprisingly enough
    DEBUG_proxy(" -got peer connection from ", clientip );

    try {
        //int rc;
#ifdef DEBUG_HIGH
        int pcount = 0;
#else
#ifdef DEBUG_LOW
        int pcount = 0;
#endif
#endif

        // assume all requests over the one persistent connection are from
        // the same user. means we only need to query the auth plugin until
        // we get credentials, then assume they are valid for all reqs. on
        // the persistent connection.
        std::string oldclientuser;
        std::string room;

        //int oldfg = 0;
        bool authed = false;
        //bool isbanneduser = false;
        //bool isscanbypass = false;
        //bool isbypass = false;
        //bool isvirusbypass = false;
        //int bypasstimestamp = 0;
        //bool iscookiebypass = false;

        AuthPlugin *auth_plugin = NULL;

        // RFC states that connections are persistent
        bool persistOutgoing = true;
        bool persistPeer = true;
        bool persistProxy = true;
        String last_domain_port;
        bool last_isdirect = false;

        bool firsttime = true;
        if (!header.in(&peerconn, true)) {     // get header from client, allowing persistency
            if (o.conn.logconerror) {
                if (peerconn.getFD() > -1) {

                    int err = peerconn.getErrno();
                    //int pport = peerconn.getPeerSourcePort();
                    std::string peerIP = peerconn.getPeerIP();

                    E2LOGGER_info("No header recd from client at ", peerIP, " - errno: %d",  err);
                } else {
                    E2LOGGER_info("Client connection closed early - no request header received");
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
            DEBUG_proxy(" firsttime =", firsttime, " ismitm =", ismitm, " clientuser =", clientuser, " group = ", filtergroup);
            ldl = o.currentLists();
            NaughtyFilter checkme(header, docheader, SBauth);
            checkme.listen_port = peerconn.getPort();
            DataBuffer docbody;
            docbody.setTimeout(o.net.exchange_timeout);
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
                DEBUG_proxy(" -persisting (count ", ++pcount, ") - ", clientip);
                header.reset();
                if (!header.in(&peerconn, true)) {
                    DEBUG_proxy(" -Persistent connection closed");
                    break;
                }
                ++dystat->reqs;

                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;

                checkme.bypasstimestamp = 0;

                authed = false;

                requestscanners.clear();
                responsescanners.clear();

                matchedip = false;
                urlparams.clear();
                postparts.clear();
                checkme.mimetype = "-";
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

            //if(o.log_requests) {
            if (e2logger.isEnabled(LoggerSource::requestlog)) {
                std::string fnt;
                if(ismitm)
                    fnt = "MITM";
                else if(header.isProxyRequest) {
                    fnt = "PROXY";
                } else fnt = "TRANS";
                doRQLog(clientuser, clientip, checkme, fnt);
            }

            if(!header.isProxyRequest)  // is transparent http proxy
                get_original_ip_port(peerconn,checkme);

            //If proxy connection is not persistent..// do this later after checking if direct or via proxy

            DEBUG_proxy("Start URL ", checkme.url, "is_ssl=", checkme.is_ssl, "ismitm=", ismitm);

            // checks for bad URLs to prevent security holes/domain obfuscation.
            if (header.malformedURL(checkme.url)) {
                // The requested URL is malformed.
                writeback_error(checkme, peerconn, 200, 0, "400 Bad Request");
                proxysock.close(); // close connection to proxy
                break;
            }

            // TODO this needs moving is proxy operation is still to be tested
            if (checkme.urldomain == o.conn.internal_test_url) {
                peerconn.writeString(
                        "HTTP/1.1 200 \nContent-Type: text/html\n\n<HTML><HEAD><TITLE>e2guardian internal test</TITLE></HEAD><BODY><H1>e2guardian internal test OK</H1> ");
                peerconn.writeString("</BODY></HTML>\n");
                proxysock.close(); // close connection to proxy
                break;
            }

            // total block list checking  now done in pre-auth story

            // don't let the client connection persist if the client doesn't want it to.
            persistOutgoing = header.isPersistent();
            // now check if in input proxy mode and direct upstream if upstream needs closing
            if (persistProxy && last_isdirect &&
            ((last_domain_port != checkme.urldomainport)|| !o.net.no_proxy)) {
                proxysock.close();
                persistProxy = false;
            }
            last_domain_port = checkme.urldomainport;
            last_isdirect = checkme.isdirect;


            //
            //
            // Now check if  machine is banned and room-based checking
            //
            //

            // is this user banned?
            //isbanneduser = false;
#ifdef NOTDEF
	if(!ismitm) {
// pretend to use xforwarded for
		clientip = "192.6.6.6";
		ip = clientip;
	}
#endif

            if (!ismitm && o.use_xforwardedfor) {
                bool use_xforwardedfor;
                if (o.net.xforwardedfor_filter_ip.size() > 0) {
                    use_xforwardedfor = false;
                    for (unsigned int i = 0; i < o.net.xforwardedfor_filter_ip.size(); i++) {
                        if (strcmp(clientip.c_str(), o.net.xforwardedfor_filter_ip[i].c_str()) == 0) {
                            use_xforwardedfor = true;
                            break;
                        }
                    }
                } else {
                    use_xforwardedfor = true;
                }
                if (use_xforwardedfor) {
                    std::string xforwardip(header.getXForwardedForIP());
                    if (xforwardip.length() > 6) {
                        clientip = xforwardip;
                        ip = clientip;
                        header.setClientIP(ip);
                    }
                    DEBUG_proxy(" -using x-forwardedfor:", clientip);
                }
            }
            checkme.clientip = clientip;

            // Look up reverse DNS name of client if needed
            if (o.conn.reverse_client_ip_lookups) {
                getClientFromIP(clientip.c_str(),checkme.clienthost);
           //     std::unique_ptr<std::deque<String> > hostnames;
           //     hostnames.reset(ipToHostname(clientip.c_str()));
           //     checkme.clienthost = std::string(hostnames->front().toCharArray());
            }

            //CALL SB pre-authcheck
            DEBUG_trace("Run   StoryA pre-authcheck");
            ldl->StoryA.runFunctEntry(ENT_STORYA_PRE_AUTH, checkme);
            DEBUG_proxy("After StoryA pre-authcheck",
                " isexception ", String(checkme.isexception),
                " isBlocked ", String(checkme.isBlocked),
                " message_no ", String(checkme.message_no));

            checkme.isItNaughty = checkme.isBlocked;
            bool isbannedip = checkme.isBlocked;
            bool part_banned;
            if (isbannedip) {
                // matchedip = clienthost == NULL;
                DEBUG_proxy("IP is banned!");
            } else {
                if (ldl->inRoom(clientip, room, &(checkme.clienthost), &isbannedip, &part_banned, &checkme.isexception,
                                checkme.urld)) {

                    DEBUG_proxy(" isbannedip = ", String(isbannedip),
                         " ispart_banned = ", String(part_banned),
                         " isexception = ", String(checkme.isexception));

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


            //
            //
            // Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            DEBUG_trace("start Authentication");
            overide_persist = false;
            if (!persistent_authed) {
                bool only_ip_auth;
                if (header.isProxyRequest) {
                    filtergroup = o.filter.default_fg;
                    SBauth.is_proxy = true;
                    if(!peerconn.down_thread_id.empty())
                        SBauth.is_tlsproxy = true;
                    only_ip_auth = false;
                } else {
                    filtergroup = o.filter.default_trans_fg;
                    SBauth.is_transparent = true;
                    only_ip_auth = true;
                }
                SBauth.group_source = "def";
                DEBUG_proxy("isProxyRequest is ", String(header.isProxyRequest),
                            " only_ip_auth is ", String(only_ip_auth) );

                if (!doAuth(checkme.auth_result, authed, filtergroup, auth_plugin, peerconn, proxysock, header, checkme,
                            only_ip_auth,
                            checkme.isconnect)) {
                    if (checkme.auth_result == E2AUTH_407_SENT) {
                        continue;
                    }
                    if ((checkme.auth_result == E2AUTH_REDIRECT) && checkme.isconnect &&
                        ldl->fg[filtergroup]->ssl_mitm) {
                        checkme.gomitm = true;
                        checkme.isdone = true;
                    } else {
                        break;
                    }
                }
            } else {
                DEBUG_proxy(" -Already got credentials for this connection - not querying auth plugins");
                authed = true;
            }
            checkme.filtergroup = filtergroup;

            docbody.set_current_config(ldl->fg[filtergroup]);
            DEBUG_proxy(" -username: " + clientuser + " -filtergroup: " + String(filtergroup));
//
// End of Authentication Checking
//
//

            //			Set if candidate for MITM
            //			(Exceptions will not go MITM)
            DEBUG_trace("ismitmcandidate");
            checkme.ismitmcandidate = checkme.isconnect && (!checkme.nomitm) && ldl->fg[filtergroup]->ssl_mitm && (header.port == 443);
            if (checkme.ismitmcandidate ) {
                if(!ldl->fg[filtergroup]->automitm) checkme.automitm = false;
            } else {
                checkme.nomitm = true;
                checkme.automitm = false;
            }

            if (checkme.urldomain == o.conn.internal_status_url) {
                peerconn.writeString(
                        "HTTP/1.1 200 \nContent-Type: text/html\n\n<HTML><HEAD><TITLE>e2guardian internal status</TITLE></HEAD><BODY><H1>e2guardian internal status OK</H1> ");
                String temp = "User: ";
                temp += clientuser;
                temp += "<br>";
                temp += "IP: ";
                temp += ip;
                temp += "<br>";
                temp += "Filtergroup: ";
                temp += ldl->fg[filtergroup]->name;
                temp += "<br>";
                temp += "Flags: ";
                temp += checkme.getFlags();
                temp += "<br>";
                temp += "e2g version: ";
                temp += PACKAGE_VERSION;
                temp += "<br>";
                temp += "Server: ";
                temp += o.net.server_name;
                temp += "<br>";
                peerconn.writeString(temp);
                peerconn.writeString("</BODY></HTML>\n");
                proxysock.close(); // close connection to proxy
                break;
            }
            //
            // Start of by pass
            //
            DEBUG_trace("checkByPass");
            if (!checkme.isdone && checkByPass(checkme, ldl, header, proxysock, peerconn, clientip)
                && sendScanFile(peerconn, checkme)) {
                persistProxy = false;
                break;
            }

            //
            // End by pass
            //

            // virus checking candidate?
            // checkme.noviruscheck defaults to true
            if (!(checkme.isdone || checkme.isconnect || checkme.ishead)    //  can't scan connect or head or not yet authed
                && !(checkme.isBlocked)  // or already blocked
                && authed   // and is authed
                && (o.plugins.csplugins.size() > 0)            //  and we have scan plugins
                && !ldl->fg[filtergroup]->disable_content_scan    // and is not disabled
                && !(checkme.isexception && !ldl->fg[filtergroup]->content_scan_exceptions)
                // and not exception unless scan exceptions enabled
                    )
                checkme.noviruscheck = false;   // note this may be reset by Storyboard to enable exceptions

            //
            // Start of Storyboard checking
            //
//            if (!(checkme.isBlocked || checkme.isbypass))
            if (!(checkme.isBlocked || checkme.isdone) && authed) {
                // Main checking is now done in Storyboard function(s)
                //   String funct = "checkrequest";
                //   ldl->fg[filtergroup]->StoryB.runFunct(funct, checkme);
                DEBUG_trace("Check StoryB checkrequest");
                ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_PROXY_REQUEST, checkme);
                DEBUG_proxy("After StoryB checkrequest",
                    " isexception ", String(checkme.isexception ),
                    " isblocked ", String(checkme.isBlocked ),
                    " gomitm ", String(checkme.gomitm),
                    " mess_no ", String(checkme.message_no)
                 );

		if (ldl->fg[filtergroup]->reporting_level != -1){
            checkme.isItNaughty = checkme.isBlocked;
		} else {
			checkme.isItNaughty = false; 
		    checkme.isBlocked = false;
		}
            }

            if (checkme.isdirect) {
                header.setDirect();
                last_isdirect = true;
                if(!o.net.no_proxy) {    // we are in mixed mode proxy and direct
                    if(persistProxy) {  // if upstream socket is open close it
                        proxysock.close();
                        persistProxy = false;
                    }
                }
            }

            if (checkme.isbypass && !(checkme.iscookiebypass || checkme.isvirusbypass)) {
                DEBUG_proxy("Setting GBYPASS cookie; bypasstimestamp = ", checkme.bypasstimestamp);
                String ud(checkme.urldomain);
                if (ud.startsWith("www.")) {
                    ud = ud.after("www.");
                }
                // redirect user to URL with GBYPASS parameter no longer appended
                String outhead = "HTTP/1.1 302 Redirect\r\n";
                outhead += "Set-Cookie: GBYPASS=";
                outhead += header.hashedCookie(&ud, ldl->fg[filtergroup]->cookie_magic.c_str(), &clientip,
                                        checkme.bypasstimestamp, clientuser).toCharArray();
               // outhead += hashedCookie(&ud, ldl->fg[filtergroup]->cookie_magic.c_str(), &clientip,
                //                        checkme.bypasstimestamp).toCharArray();
                outhead += "; path=/; domain=.";
                outhead += ud;
                outhead += "\r\n";
                outhead += "Location: ";
                outhead += checkme.logurl.before("GBYPASS=");
                outhead.chop();
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
            if (!checkme.isdone) {
                if (checkme.isGrey && checkme.isSearch)
                    check_search_terms(checkme);
            }  // will set isItNaughty if needed


            // TODO V5 call POST scanning code New NaughtyFilter function????

            // don't run willScanRequest if content scanning is disabled, or on exceptions if contentscanexceptions is off,
            // or on SSL (CONNECT) requests, or on HEAD requests, or if in AV bypass mode

            //if not naughty now send upstream and get response
            if (checkme.isItNaughty) {
                if (checkme.isconnect && checkme.automitm) {
                    checkme.gomitm = true;   // so that we can deliver a status message to user over half MITM
                    if (checkme.isdirect) {  // send connection estabilished to client
                        std::string msg = "HTTP/1.1 200 Connection established\r\n\r\n";
                        if (!peerconn.writeString(msg.c_str())) {
                            peerDiag("Unable to send 200 connection  established to client ", peerconn);
                            break;
                        }
                    }
                } else {
                    checkme.gomitm = false;   // if not automitm
                }
            } else {
                if (!persistProxy) // open upstream connection
                {
                    int out_port = header.port;
                    if (o.conn.use_original_ip_port && checkme.got_orig_ip &&
                        !header.isProxyRequest)
                        out_port = checkme.orig_port;
                    if (connectUpstream(proxysock, checkme, out_port) < 0) {
                        if (checkme.isconnect && checkme.automitm &&
                            checkme.upfailure)
                        {
                            checkme.gomitm = true;   // so that we can deliver a status message to user over half MITM
                        // to give error - depending on answer
                        // timeout -etc
                        } else {
                       //     checkme.gomitm = false;   // if not automitm
                        }
                    }
                }
                if (!checkme.upfailure) {
                    if (!proxysock.readyForOutput(o.net.proxy_timeout)) {
                        upstreamDiag("Unable to write upstream", proxysock);
                        break;
                    }
                }
                if (checkme.isdirect && checkme.isconnect) {  // send connection estabilished to client
                    std::string msg = "HTTP/1.1 200 Connection established\r\n\r\n";
                    if (!peerconn.writeString(msg.c_str())) {
                        peerDiag("Unable to send 200 connection  established to client ", peerconn);
                        break;
                    }
                } else if (!checkme.upfailure)  // in all other cases send header upstream and get response
                {
                    if (!(header.out(&peerconn, &proxysock, __E2HEADER_SENDALL, true) // send proxy the request
                          && (docheader.in_handle_100(&proxysock, persistOutgoing, header.expects_100)))) {
                        if (proxysock.isTimedout()) {
//                            writeback_error(checkme, peerconn, 203, 204, "408 Request Time-out");
                            writeback_error(checkme, peerconn, 0, 0, "408 Request Time-out");
                        } else {
			                if(!ismitm) {
                                writeback_error(checkme, peerconn, 0, 0, "408 Request Time-out");
                                //writeback_error(checkme, peerconn, 205, 206, "502 Gateway Error");
			                }
                        }
                        persistPeer = false;
                        persistProxy = false;
                        break;
                    }
                    persistProxy = docheader.isPersistent();
                    persistPeer = persistOutgoing && docheader.wasPersistent();

                    DEBUG_proxy(" -persistPeer: ", String(persistPeer));

                    //check response code
                    if ((!checkme.isItNaughty) && (!checkme.upfailure)) {
                        int rcode = docheader.returnCode();
                        if (rcode == 407) {   // proxy auth required
                            // tunnel thru -  may be content
                            checkme.tunnel_rest = true;
                            checkme.tunnel_2way = false;
                            // treat connect like normal get
                            checkme.isconnect = false;
                            checkme.isexception = true;
                        }
                        if (checkme.isconnect) {
                            if (rcode == 200) {
                                persistProxy = false;
                                persistPeer = false;
                            } else {        // some sort of problem
                                checkme.ismitmcandidate = false;  // only applies to connect
                                checkme.tunnel_rest = true;
                                checkme.tunnel_2way = false;
                            }
                        }

                        if (docheader.contentLength() == 0)   // no content
                            checkme.tunnel_rest = true;

                    }
                }

                if (checkme.isconnect && checkme.isGrey) {  // allow legacy SSL behavour when mitm not enabled
                    checkme.tunnel_2way = true;
                    checkme.tunnel_rest = false;
                }
            }
            if ((checkme.isexception || checkme.logcategory) && !checkme.upfailure) {
                if (checkme.isconnect) {
                    checkme.tunnel_2way = true;
                    checkme.tunnel_rest = false;
                    persistPeer = false;
                    persistProxy = false;
                } else {
                    if (!checkme.noviruscheck && !ldl->fg[filtergroup]->content_scan_exceptions)
                        checkme.noviruscheck = true;
                    if (checkme.noviruscheck) {
                        checkme.tunnel_2way = false;
                        checkme.tunnel_rest = true;
                    }
                }
            }

            //if ismitm - GO MITM
            // ssl_grey is covered in storyboard
            if (!checkme.tunnel_rest && checkme.isconnect && checkme.gomitm)
            {
                DEBUG_proxy("Going MITM ....");
                if(!ldl->fg[filtergroup]->mitm_check_cert)
                    checkme.nocheckcert = true;
                goMITM(checkme, proxysock, peerconn, persistProxy, authed, persistent_authed, ip, dystat, clientip,checkme.isdirect);
                persistPeer = false;
                persistProxy = false;
                //if (!checkme.isItNaughty) // surely we should just break here whatever? - No we need to log error
                    break;
            }

            //CALL SB checkresponse
            if ((!checkme.isItNaughty) && (!checkme.upfailure) && (!checkme.isconnect) && (!checkme.logcategory) && !checkme.tunnel_rest) {
                ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_PROXY_RESPONSE, checkme);
                DEBUG_proxy("After StoryB checkresponse ",
                    " IsException ", String(checkme.isexception),
                    " IsBlocked ", String(checkme.isBlocked),
                    " mess_no ", String(checkme.message_no) );

		if (ldl->fg[filtergroup]->reporting_level != -1){
            checkme.isItNaughty = checkme.isBlocked;
		} else {
			checkme.isItNaughty = false; 
		    checkme.isBlocked = false;
		    checkme.isGrey = true;
		}

                if (checkme.ishead || (docheader.contentLength() == 0 && !docheader.chunked))
                    checkme.tunnel_rest = true;

                if (checkme.isexception && !ldl->fg[filtergroup]->content_scan_exceptions) {
                    checkme.tunnel_rest = true;
                    checkme.noviruscheck = true;
                }

                if (!checkme.noviruscheck) {
                    for (std::deque<Plugin *>::iterator i = o.plugins.csplugins_begin; i != o.plugins.csplugins_end; ++i) {
                        int csrc = ((CSPlugin *) (*i))->willScanRequest(header.getUrl(), clientuser.c_str(),
                                                                        ldl->fg[filtergroup], clientip.c_str(), false,
                                                                        false, checkme.isexception, checkme.isbypass);
                        if (csrc > 0)
                            responsescanners.push_back((CSPlugin *) (*i));
                        else if (csrc < 0)
                            E2LOGGER_error("willScanRequest returned error: ", csrc);
                    }
                    DEBUG_proxy(" -Content scanners interested in response data: ", responsescanners.size());
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
                if (!docheader.out(NULL, &peerconn, __E2HEADER_SENDALL, false)) {
                    peerDiag("Unable to send return header to client", peerconn);
                    break;
                }

                if ((!checkme.isItNaughty) && checkme.waschecked) {
                    if (docbody.dontsendbody && docbody.tempfilefd > -1) {
//#ifdef NOTDEF
                        // must have been a 'fancy'
                        // download manager so we need to send a special link which
                        // will get recognised and cause DG to send the temp file to
                        // the browser.  The link will be the original URL with some
                        // magic appended to it like the bypass system.

                        // format is:
                        // GSBYPASS=hash(ip+url+tempfilename+mime+disposition+secret)
                        // &N=tempfilename&M=mimetype&D=dispos

                        String ip(clientip);
                        String tempfilename(docbody.tempfilepath.after("/tf"));
                        String tempfilemime(docheader.getContentType());
                        String tempfiledis(miniURLEncode(docheader.disposition().toCharArray()).c_str());
                        String secret(ldl->fg[filtergroup]->magic.c_str());
                        String magic(ip + checkme.url + tempfilename + tempfilemime + tempfiledis + secret);
                        String hashed(magic.md5());
#ifdef DGDEBUG
                        std::cout << dbgPeerPort << " -sending magic link to client: " << ip << " " << url << " " << tempfilename << " " << tempfilemime << " " << tempfiledis << " " << secret << " " << hashed << std::endl;
#endif
                        String sendurl(checkme.url);
                        if (!sendurl.after("://").contains("/")) {
                            sendurl += "/";
                        }
                        if (sendurl.contains("?")) {
                            sendurl += "&GSBYPASS=";
                        } else {
                            sendurl += "?GSBYPASS=";
                        }
                        sendurl += hashed;
                        sendurl += "&N=";
                        sendurl += tempfilename;
                        sendurl += "&M=";
                        sendurl += tempfilemime;
                        sendurl += "&D=";
                        sendurl += tempfiledis;
                        docbody.dm_plugin->sendLink(peerconn, sendurl, checkme.url);

                        // can't persist after this - DM plugins don't generally send a Content-Length.
                        //TODO: need to change connection: close if there is plugin involved.
                        persistOutgoing = false;
//#endif
                    } else {
                        if (!docbody.out(&peerconn)) {
                            DEBUG_network(" docbody.out returned error");
                            checkme.pausedtoobig = false;
                        }
                        if (checkme.pausedtoobig)
                            checkme.tunnel_rest = true;
                    }
                }
            }

            //if not grey tunnel response
            if (!checkme.isItNaughty) {
                if (checkme.tunnel_rest) {
                    bool chunked = docheader.transferEncoding().contains("chunked");
                    DEBUG_proxy(" -Tunnelling to client");
                    DEBUG_proxy(" - Content-Length:", docheader.contentLength(), " cm.docsize:", checkme.docsize);

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


            DEBUG_proxy(" -Forwarding body to client :",
                        " Upfailure is ", String(checkme.upfailure),
                        " isItNaughty is ", String(checkme.isItNaughty));

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
        DEBUG_proxy(" -connection handler caught an exception: ", e.what());
        if (o.conn.logconerror)
            E2LOGGER_error("-connection handler caught an exception %s", e.what());

        // close connection to proxy
        proxysock.close();
        return -1;
    }
    if (!ismitm)
        try {
            DEBUG_proxy(" -Attempting graceful connection close");
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
            DEBUG_debug(" -connection handler caught an exception on connection closedown: ", e.what() );
            // close connection to the client
            peerconn.close();
            proxysock.close();
        }

    return 0;
}


void ConnectionHandler::doLog(std::string &who, std::string &from, NaughtyFilter &cm) {

    DEBUG_trace("who: ", who, " from: ", from );

    struct timeval theend;
    gettimeofday(&theend, NULL);
    String rtype = cm.request_header->requestType();
    String where = cm.get_logUrl();
    unsigned int port = cm.request_header->port;
    std::string what;

    ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_LOG_CHECK, cm);
    if(cm.nolog) return;

    // if(o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        what = thread_id;
    }
    what += cm.whatIsNaughtyLog;
    String how = rtype;
    off_t size = cm.docsize;
    std::string *cat = &cm.whatIsNaughtyCategories;
    bool isnaughty = cm.isItNaughty;
    int naughtytype = cm.blocktype;
    bool isexception = cm.isexception;
    bool istext = cm.is_text;
    struct timeval *thestart = &cm.thestart;
    bool cachehit = false;
    //int code = (cm.wasrequested ? cm.response_header->returnCode() : 200);  //cm.wasrequested is never set anywhere!!
    int code = (cm.response_header->returnCode());
    if (isnaughty) code = 403;
    std::string mimetype = cm.response_header->getContentType();
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
            (o.log.log_level == 0) || ((cat != NULL) && !o.log.log_ad_blocks && (strstr(cat->c_str(), "ADs") != NULL)) ||
            ((o.log.log_exception_hits == 0) && isexception)) {
        if (o.log.log_level != 0) {
            if (isexception) {
                DEBUG_debug(" -Not logging exceptions");
            } else {
                DEBUG_debug(" -Not logging 'ADs' blocks");
            }
        }
        return;
    }

    std::string data, cr("\n");

    if ((isexception && (o.log.log_exception_hits == 2))
        || isnaughty || o.log.log_level == 3 || (o.log.log_level == 2 && istext)) {
        // put client hostname in log if enabled.
        // for banned & exception IP/hostname matches, we want to output exactly what was matched against,
        // be it hostname or IP - therefore only do lookups here when we don't already have a cached hostname,
        // and we don't have a straight IP match agaisnt the banned or exception IP lists.
        if (o.log.log_client_hostnames && (cm.clienthost == "") && !matchedip && !cm.anon_user) {
            DEBUG_debug("logclienthostnames enabled but reverseclientiplookups disabled; lookup forced.");
            getClientFromIP(from.c_str(),cm.clienthost);
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

        // Item length limit put back to avoid log listener
        // overload with very long urls Philip Pearce Jan 2014
        if ((cat != NULL) && (cat->length() > o.log.max_logitem_length))
            cat->resize(o.log.max_logitem_length);
        if (what.length() > o.log.max_logitem_length)
            what.resize(o.log.max_logitem_length);
        if (where.length() > o.log.max_logitem_length)
            where.limitLength(o.log.max_logitem_length);
        if (o.log.dns_user_logging() && !is_real_user) {
            String user;
            if (getdnstxt(from, user)) {
                who = who + ":" + user;
                SBauth.user_name = user;
                SBauth.user_source = "dnslog";
            };
            is_real_user = true;    // avoid looping on persistent connections
        };
        std::string l_who = who;
        std::string l_from = from;
        std::string l_clienthost;
        l_clienthost = cm.clienthost;

        if (cm.anon_user) {
            l_who = "";
            l_from = "0.0.0.0";
            l_clienthost = "";
        }

        // populate flags field
        String flags = cm.getFlags();

        DEBUG_debug(" -Building raw log data string... ");

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
        data += String((theend).tv_sec) + cr;
        data += String((theend).tv_usec) + cr;
        data += l_clienthost + cr;

        if (o.log.log_user_agent)
            data += (reqheader ? reqheader->userAgent() + cr : cr);
        else
            data += cr;
        data += urlparams + cr;
        data += postdata.str().c_str() + cr;
        data += String(message_no) + cr;
        data += String(headeradded) + cr;
        data += flags + cr;
        data += cm.search_terms;
        data += cr;

        DEBUG_debug(" -...built");

        //delete newcat;
        // push on log queue
        o.log.log_Q->push(data);
        // connect to dedicated logging proc
    }
}

void ConnectionHandler::doRQLog(std::string &who, std::string &from, NaughtyFilter &cm, std::string &funct) {
    DEBUG_trace("who: ", who, " from: ", from, "funct: ", funct);
    String rtype = cm.request_header->requestType();
    String where = cm.logurl;
    unsigned int port = cm.request_header->port;
    std::string what = thread_id;
    what += funct;
    if (cm.isTLS)
        what += "_TLS";
    if (cm.hasSNI)
        what += "_SNI";
    if (cm.ismitm)
        what += "_MITM";
    String how = rtype;
    off_t size = cm.docsize;
    std::string *cat = nullptr;  //&cm.whatIsNaughtyCategories;
    bool isnaughty = cm.isItNaughty;
    int naughtytype = cm.blocktype;
    bool isexception = cm.isexception;
    struct timeval *thestart = &cm.thestart;
    bool cachehit = false;
    int code = 0;
    std::string mimetype = "";  //cm.mimetype;
    bool wasinfected = false;  //cm.wasinfected;
    bool wasscanned = false;  //cm.wasscanned;
    int naughtiness = 0;  //cm.naughtiness;
    int filtergroup = cm.filtergroup;
    HTTPHeader *reqheader = cm.request_header;
    int message_no = cm.message_no;
    bool contentmodified = false; //cm.contentmodified;
    bool urlmodified = false; //cm.urlmodified;
    bool headermodified = false; //cm.headermodified;
    bool headeradded = false; //cm.headeradded;

    std::string data, cr("\n");

//    if ((isexception && (o.log_exception_hits == 2))
//        || isnaughty || o.ll == 3 || (o.ll == 2 && istext)) 
    if(true) {

        // Item length limit put back to avoid log listener
        // overload with very long urls Philip Pearce Jan 2014
        if (what.length() > o.log.max_logitem_length)
            what.resize(o.log.max_logitem_length);
        if (where.length() > o.log.max_logitem_length)
            where.limitLength(o.log.max_logitem_length);
        if (o.log.dns_user_logging() && !is_real_user) {
            String user;
            if (getdnstxt(from, user)) {
                who = who + ":" + user;
            };
            is_real_user = true;    // avoid looping on persistent connections
        };
        std::string l_who = who;
        std::string l_from = from;
        std::string l_clienthost;
        l_clienthost = cm.clienthost;
        String flags = cm.getFlags();

        DEBUG_debug(" -Building raw log data string... ");

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
        data += String((*thestart).tv_sec) + cr;
        data += String((*thestart).tv_usec) + cr;
        data += l_clienthost + cr;
        if (o.log.log_user_agent)
            data += (reqheader ? reqheader->userAgent() + cr : cr);
        else
            data += cr;
        data += urlparams + cr;
        data += cr;
        data += String(message_no) + cr;
        data += String(headeradded) + cr;
        data += flags + cr;
        data += cr;     //cm.search_terms not known yet
        data += cr;

        DEBUG_debug(" -...built");

        //delete newcat;
        // push on log queue
        o.log.RQlog_Q->push(data);
        // connect to dedicated logging proc
    }
}



// based on patch by Aecio F. Neto (afn@harvest.com.br) - Harvest Consultoria (http://www.harvest.com.br)
// show the relevant banned page/image/CGI based on report level setting, request type etc.
bool ConnectionHandler::genDenyAccess(Socket &peerconn, String &eheader, String &ebody, HTTPHeader *header,
                                      HTTPHeader *docheader,
                                      String *url, NaughtyFilter *checkme, std::string *clientuser,
                                      std::string *clientip, int filtergroup,
                                      bool ispostblock, int headersent, bool wasinfected, bool scanerror,
                                      bool forceshow) {
    int reporting_level = ldl->fg[filtergroup]->reporting_level;
    DEBUG_debug(" -reporting level is ", reporting_level);
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
        String flags = checkme->getFlags();
        if (reporting_level > 0) {
            // generate a filter bypass hash
            if (!wasinfected && (checkme->isbypassallowed) && !ispostblock) {
                DEBUG_debug(" -Enabling filter bypass hash generation");
                filterhash = true;
                if (ldl->fg[filtergroup]->bypass_mode > 0 )
                    dohash = true;
            }
                // generate an infection bypass hash
            else if (wasinfected && checkme->isinfectionbypassallowed) {
                // only generate if scanerror (if option to only bypass scan errors is enabled)
                if ((*ldl->fg[filtergroup]).infection_bypass_errors_only ? scanerror : true) {
                    DEBUG_debug(" -Enabling infection bypass hash generation");
                    virushash = true;
                    if (ldl->fg[filtergroup]->infection_bypass_mode > 0)
                        dohash = true;
                }
            }
        }
        DEBUG_debug(" - filter bypass hash generation", " virushah ", virushash, " dohash", dohash, " filterhash ", filterhash);

// the user is using the full whack of custom banned images and/or HTML templates
        if (reporting_level == 3 || (headersent > 0 && reporting_level > 0) || forceshow || (*header).requestType().startsWith("CONNECT"))
        {

            // if reporting_level = 1 or 2 and headersent then we can't
            // send a redirect so we have to display the template instead


            if ((*header).requestType().startsWith("CONNECT") && !(peerconn).isSsl())
            {
        // Block ssl website    
        // Buggy with FF < 65 https://bugzilla.mozilla.org/show_bug.cgi?id=1522093
	// Connections still opened after a refresh 
	// 403 requests made ICAP error with high load
		eheader = "HTTP/1.1 302 Redirect";
		eheader += "\r\nLocation: http://internal.test.e2guardian.org";
		eheader += "\r\nServer: e2guardian";
		eheader += "\r\nConnection: close";
		eheader += "\r\n\r\n";
	    } else {
                // we're dealing with a non-SSL'ed request, and have the option of using the custom banned image/page directly
                bool replaceimage = false;
                bool replaceflash = false;
                if (o.block.use_custom_banned_image) {

                    // It would be much nicer to do a mime comparison
                    // and see if the type is image/* but the header
                    // never (almost) gets back from squid because
                    // it gets denied before then.
                    // This method is prone to over image replacement
                    // but will work most of the time.

                    String lurl((*url));
                    lurl.toLower();
                    if (lurl.endsWith(".gif") || lurl.endsWith(".jpg") || lurl.endsWith(".jpeg") ||
                        lurl.endsWith(".jpe")
                        || lurl.endsWith(".png") || lurl.endsWith(".bmp") ||
                        (*docheader).isContentType("image/", ldl->fg[filtergroup])) {
                        replaceimage = true;
                    }
                }

                if (o.block.use_custom_banned_flash) {
                    String lurl((*url));
                    lurl.toLower();
                    if (lurl.endsWith(".swf") ||
                        (*docheader).isContentType("application/x-shockwave-flash", ldl->fg[filtergroup])) {
                        replaceflash = true;
                    }
                }

                // if we're denying an image request, show the image; otherwise, show the HTML page.
                // (or advanced ad block page, or HTML page with bypass URLs)
                if (replaceimage) {
                    if (headersent == 0) {
                        eheader = "HTTP/1.1 200 OK\r\n";
                    }
                    o.block.banned_image.display_hb(eheader, ebody);
                } else if (replaceflash) {
                    if (headersent == 0) {
                        eheader = "HTTP/1.1 200 OK\r\n";
                    }
                    o.block.banned_flash.display_hb(eheader, ebody);
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
                            hashed = header->hashedURL(url, clientip, virushash, clientuser, *ldl->fg[filtergroup]);
                        }
                            // otherwise, just generate flags showing what to generate
                        else if (filterhash) {
                            hashed = "HASH=1";
                        } else if (virushash) {
                            hashed = "HASH=2";
                        }

                        if(ldl->fg[filtergroup]->cgi_bypass_v2) {
                            if (filterhash) {
                                hashed += "&HASH=1";
                            } else if (virushash) {
                                hashed += "&HASH=2";
                            }
                        }

                        if (headersent == 0) {
                            eheader = "HTTP/1.1 200 \r\n";
                        }
                        if (headersent < 2) {
                            eheader += "Content-type: text/html\r\n\r\n";
                        }
                        // if the header has been sent then likely displaying the
                        // template will break the download, however as this is
                        // only going to be happening if the unsafe trickle
                        // buffer method is used and we want the download to be
                        // broken we don't mind too much
                        //String fullurl = header->getLogUrl(true);
			//
			// DISPLAYING TEMPLATE

                        String fullurl = checkme->get_logUrl();
                        String localip = peerconn.getLocalIP();
                        ldl->fg[filtergroup]->getHTMLTemplate(checkme->upfailure)->display_hb(ebody,
                                                                                              &fullurl,
                                                                                              (*checkme).whatIsNaughty,
                                                                                              (*checkme).whatIsNaughtyLog,
                                // grab either the full category list or the thresholded list
                                                                                              (checkme->usedisplaycats
                                                                                               ? checkme->whatIsNaughtyDisplayCategories
                                                                                               : checkme->whatIsNaughtyCategories),
                                                                                              clientuser, clientip,
                                                                                              &(checkme->clienthost),
                                                                                              filtergroup,
                                                                                              ldl->fg[filtergroup]->name,
                                                                                              hashed, localip, flags);
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
                hashed = header->hashedURL(url, clientip, virushash, clientuser, *ldl->fg[filtergroup]);
                //hashed = hashedURL(url, filtergroup, clientip, virushash, clientuser);
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
                (*checkme).whatIsNaughtyLog = String((*checkme).whatIsNaughtyLog.c_str()).subString(0,
                                                                                                    2048).toCharArray();
            }

            if ((*header).requestType().startsWith("CONNECT") && !(peerconn).isSsl())
		{
        // Block ssl website    
        // Buggy with FF < 65 https://bugzilla.mozilla.org/show_bug.cgi?id=1522093
	// Connections still opened after a refresh 
	// 403 requests made ICAP error with high load
		eheader = "HTTP/1.1 302 Redirect";
		eheader += "\r\nLocation: http://internal.test.e2guardian.org";
		eheader += "\r\nServer: e2guardian";
		eheader += "\r\nConnection: close";
		eheader += "\r\n\r\n";
                // we're dealing with a non-SSL'ed request, and have the option of using the custom banned image/page directly
	    } else {
	    	eheader = "HTTP/1.1 302 Redirect\r\n";
            	eheader += "Location: ";
           	eheader += ldl->fg[filtergroup]->access_denied_address;
	    }
            if (ldl->fg[filtergroup]->non_standard_delimiter) {
                eheader += "?DENIEDURL==";
                eheader += miniURLEncode((*url).toCharArray()).c_str();
                eheader += "::IP==";
                eheader += (*clientip).c_str();
                eheader += "::USER==";
                eheader += (*clientuser).c_str();
                eheader += "::FILTERGROUP==";
                eheader += ldl->fg[filtergroup]->name;
                if (checkme->clienthost != "") {
                    eheader += "::HOST==";
                    eheader += checkme->clienthost.c_str();
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
                    if(ldl->fg[filtergroup]->cgi_bypass_v2) {
                        String data = *clientip;
                        data += *clientuser;
                        data += ldl->fg[filtergroup]->cgi_magic;
                        String checkh(url->md5(data.c_str()));
                        eheader += "::CHECK==";
                        eheader += checkh.toCharArray();
                    }
                }
                eheader += "::EXTFLAGS==";
                eheader += flags.toCharArray();
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
                if (checkme->clienthost != "") {
                    eheader += "&HOST=";
                    eheader += checkme->clienthost.c_str();
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
                    if(ldl->fg[filtergroup]->cgi_bypass_v2) {
                        String data = *clientip;
                        data += *clientuser;
                        data += ldl->fg[filtergroup]->cgi_magic;
                        String checkh(url->md5(data.c_str()));
                        eheader += "&CHECK=";
                        eheader += checkh.toCharArray();
                    }
                }
                eheader += "&EXTFLAGS=";
                eheader += flags.toCharArray();
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
                                   String *url, NaughtyFilter *checkme, std::string *clientuser, std::string *clientip,
                                   int filtergroup,
                                   bool ispostblock, int headersent, bool wasinfected, bool scanerror, bool forceshow) {
    String eheader, ebody;
    if (genDenyAccess(*peerconn, eheader, ebody, header, docheader, &(checkme->logurl), checkme, clientuser, clientip, filtergroup,
                      ispostblock, headersent, wasinfected, scanerror, forceshow)) {
        peerconn->writeString(eheader.toCharArray());
        if (ebody.length() > 0)
            peerconn->writeString(ebody.toCharArray());
    };

    // we blocked the request, so flush the client connection & close the proxy connection.
    if ((*checkme).isItNaughty) {
        (*peerconn).readyForOutput(o.net.proxy_timeout); //as best a flush as I can
        (*proxysock).close(); // close connection to proxy
        // we said no to the request, so return true, indicating exit the connhandler
        return true;
    }
    ldl.reset();
    return false;
}    // end of deny request loop

// do content scanning (AV filtering) and naughty filtering
void ConnectionHandler::contentFilter(HTTPHeader *docheader, HTTPHeader *header, DataBuffer *docbody,
                                      Socket *proxysock, Socket *peerconn, int *headersent, bool *pausedtoobig,
                                      off_t *docsize, NaughtyFilter *checkme,
                                      bool wasclean, int filtergroup, std::deque<CSPlugin *> &responsescanners,
                                      std::string *clientuser, std::string *clientip, bool *wasinfected,
                                      bool *wasscanned, bool isbypass,
                                      String &url, String &domain, bool *scanerror, bool &contentmodified,
                                      String *csmessage) {
    //int rc = 0;

    //proxysock->bcheckForInput(120000);
    bool compressed = docheader->isCompressed();
    if (compressed) {
        DEBUG_debug(" -Decompressing as we go.....");
        docbody->setDecompress(docheader->contentEncoding());
    }
    DEBUG_debug(docheader->contentEncoding());
    DEBUG_debug(" -about to get body from proxy");
    (*pausedtoobig) = docbody->in(proxysock, peerconn, header, docheader, !responsescanners.empty(),
                                  headersent, ldl->fg[filtergroup]->StoryB, checkme ); // get body from proxy
// checkme: surely if pausedtoobig is true, we just want to break here?
// the content is larger than max_content_filecache_scan_size if it was downloaded for scanning,
// and larger than max_content_filter_size if not.
// in fact, why don't we check the content length (when it's not -1) before even triggering the download managers?
    if ((*pausedtoobig)) {
        DEBUG_debug(" -got PARTIAL body ");
    } else {
        DEBUG_debug(" -got body");
    }

    off_t dblen;
    bool isfile = false;
    if (docbody->tempfilesize > 0) {
        dblen = docbody->tempfilesize;
        isfile = true;
    } else {
        dblen = docbody->data_length;
    }
    // don't scan zero-length buffers (waste of AV resources, especially with external scanners (ICAP)).
    // these were encountered browsing opengroup.org, caused by a stats script. (PRA 21/09/2005)
    // if we wanted to honour a hypothetical min_content_scan_size, we'd do it here.
    if (((*docsize) = dblen) == 0) {
        DEBUG_debug(" -Not scanning zero-length body");
        // it's not inconceivable that we received zlib or gzip encoded content
        // that is, after decompression, zero length. we need to cater for this.
        // seen on SW's internal MediaWiki.
        docbody->swapbacktocompressed();
        return;
    }

    if (!wasclean) { // was not clean or no urlcache

        // fixed to obey maxcontentramcachescansize
        if (!responsescanners.empty() &&
            (isfile ? dblen <= o.content.max_content_filecache_scan_size : dblen <= o.content.max_content_ramcache_scan_size)) {
            int csrc = 0;
            int k = 0;

            for (std::deque<CSPlugin *>::iterator i = responsescanners.begin(); i != responsescanners.end(); i++) {
                (*wasscanned) = true;
                if (isfile) {
                    DEBUG_debug(" -Running scanFile");
                    csrc = (*i)->scanFile(header, docheader, clientuser->c_str(), ldl->fg[filtergroup],
                                          clientip->c_str(), docbody->tempfilepath.toCharArray(), checkme);
                    if ((csrc != E2CS_CLEAN) && (csrc != E2CS_WARNING)) {
                        unlink(docbody->tempfilepath.toCharArray());
                        // delete infected (or unscanned due to error) file straight away
                    }
                } else {
                    DEBUG_debug(" -Running scanMemory");
                    csrc = (*i)->scanMemory(header, docheader, clientuser->c_str(), ldl->fg[filtergroup],
                                            clientip->c_str(), docbody->data, docbody->data_length, checkme);
                }
                DEBUG_debug(" -AV scan ", k, " returned: ", csrc);
                if (csrc == E2CS_WARNING) {
                    // Scanner returned a warning. File wasn't infected, but wasn't scanned properly, either.
                    (*wasscanned) = false;
                    (*scanerror) = false;
                    DEBUG_debug((*i)->getLastMessage());
                    (*csmessage) = (*i)->getLastMessage();
                } else if (csrc == E2CS_BLOCKED) {
                    (*wasscanned) = true;
                    (*scanerror) = false;
                    break;
                } else if (csrc == E2CS_INFECTED) {
                    (*wasinfected) = true;
                    (*scanerror) = false;
                    break;
                }
                    //if its not clean / we errored then treat it as infected
                else if (csrc != E2CS_CLEAN) {
                    if (csrc < 0) {
                        E2LOGGER_error("Unknown return code from content scanner: ", csrc);
                        if (ldl->fg[filtergroup]->disable_content_scan_error) {
                            E2LOGGER_error( "disablecontentscanerror is on : bypass actived USER: ", clientip, " URL: ", url);
                            (*wasscanned) = false;
                            (*wasinfected) = false;
                            break;
                        }
                    } else {
                        E2LOGGER_error("scanFile/Memory returned error: ", csrc);
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
                k++;
            }

            DEBUG_debug(" -finished running AV");
//            rc = system("date");
        }
        else if (!responsescanners.empty()) {
            DEBUG_debug(" -content length large so skipping content scanning (virus) filtering");
        }
//        rc = system("date");
        if (!checkme->isItNaughty && !checkme->isException && !isbypass && (dblen <= o.content.max_content_filter_size)
            && !docheader->authRequired() && (docheader->isContentType("text", ldl->fg[filtergroup]) ||
                                              docheader->isContentType("-", ldl->fg[filtergroup]))) {
            DEBUG_debug(" -Start content filtering: ");
            checkme->checkme(docbody->data, docbody->buffer_length, &url, &domain,
                             ldl->fg[filtergroup], ldl->fg[filtergroup]->banned_phrase_list,
                             ldl->fg[filtergroup]->naughtyness_limit);
            DEBUG_debug(" -Done content filtering");
        }

        else {
            DEBUG_debug(" -Skipping content filtering: ");
            if (dblen > o.content.max_content_filter_size) {
                DEBUG_debug(" -Content too large");
            } else if (checkme->isException) {
                DEBUG_debug(" -Is flagged as an exception");
            } else if (checkme->isItNaughty) {
                DEBUG_debug(" -Is already flagged as naughty (content scanning)");
            } else if (isbypass) {
              DEBUG_debug(" -Is flagged as a bypass");
            } else if (docheader->authRequired()) {
                DEBUG_debug(" -Is a set of auth required headers");
            } else if (!docheader->isContentType("text",ldl->fg[filtergroup])) {
                DEBUG_debug(" -Not text");
            }
        }
    }

    // don't do phrase filtering or content replacement on exception/bypass accesses
    if (checkme->isException || isbypass) {
        // don't forget to swap back to compressed!
        docbody->swapbacktocompressed();
        return;
    }

    if ((dblen <= o.content.max_content_filter_size) && !checkme->isItNaughty &&
        docheader->isContentType("text", ldl->fg[filtergroup])) {
        contentmodified = docbody->contentRegExp(ldl->fg[filtergroup]);
        // content modifying uses global variable
    }

    else {
        DEBUG_debug(" -Skipping content modification: ");
        if (dblen > o.content.max_content_filter_size) {
          DEBUG_debug(" -Content too large");
        } else if (!docheader->isContentType("text",ldl->fg[filtergroup])) {
            DEBUG_debug(" -Not text");
        } else if (checkme->isItNaughty) {
          DEBUG_debug(" -Already flagged as naughty");
        }
    }
    //rc = system("date");

    if (contentmodified) { // this would not include infected/cured files
        // if the content was modified then it must have fit in ram so no
        // need to worry about swapped to disk stuff
        DEBUG_debug(" -content modification made");
        if (compressed) {
            docheader->removeEncoding(docbody->data_length);
            // need to modify header to mark as not compressed
            // it also modifies Content-Length as well
        } else {
            docheader->setContentLength(docbody->data_length);
        }
    } else {
        docbody->swapbacktocompressed();
        // if we've not modified it might as well go back to
        // the original compressed version (if there) and send
        // that to the browser
    }
    DEBUG_debug(" Returning from content checking");
}


int ConnectionHandler::sendProxyConnect(String &hostname, Socket *sock, NaughtyFilter *checkme) {
    String connect_request = "CONNECT " + hostname + ":";
    connect_request += "443 HTTP/1.1\r\n\r\n";

    DEBUG_debug(" -creating tunnel through proxy to ", hostname);

    //somewhere to hold the header from the proxy
    HTTPHeader header(__HEADER_RESPONSE);
    //header.setTimeout(o.pcon_timeout);
    header.setTimeout(o.net.proxy_timeout);

    if (!(sock->writeString(connect_request.c_str()) && header.in(sock, true))) {

        DEBUG_debug(" -Error creating tunnel through proxy", strerror(errno) );
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
        (*checkme).whatIsNaughtyLog = (*checkme).whatIsNaughty + " with error code " + String(header.returnCode());
        (*checkme).isItNaughty = true;
        (*checkme).whatIsNaughtyCategories = o.language_list.getTranslation(70);

        DEBUG_debug(" -Tunnel status was ", header.returnCode(), " expecting 200 ok");

        return -1;
    }

    return 0;
}

void ConnectionHandler::checkCertificate(String &hostname, Socket *sslsock, NaughtyFilter *checkme)
{
    DEBUG_debug(" -checking SSL certificate is valid");

    long rc = sslsock->checkCertValid(hostname);
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

    DEBUG_debug(" -checking SSL certificate hostname");

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


bool ConnectionHandler::getdnstxt(std::string &clientip, String &user) {

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

    DEBUG_debug("IPPath is ", ippath);

    // change '.' to '-'
    ippath.swapChar('.', '-');
    DEBUG_debug("IPPath is ", ippath);
#ifdef PRT_DNSAUTH
    // get info from DNS
    union {
        HEADER hdr;
        u_char buf[NS_PACKETSZ];
    } response;
    int responseLen;
    ns_msg handle; /* handle for response message */
    responseLen = res_querydomain(ippath.c_str(), o.log.dns_user_logging_domain.c_str(), ns_c_in, ns_t_txt, (u_char *)&response, sizeof(response));
    if (responseLen < 0) {
        DEBUG_debug("DNS query returned error ", dns_error(h_errno));
        return false;
    }
    if (ns_initparse(response.buf, responseLen, &handle) < 0) {
        DEBUG_debug("ns_initparse returned error ", strerror(errno));
        return false;
    }
    //int rrnum; /* resource record number */
    ns_rr rr; /* expanded resource record */
    //u_char *cp;
    //char ans[MAXDNAME];

    int i = ns_msg_count(handle, ns_s_an);
    if (i > 0) {
        if (ns_parserr(&handle, ns_s_an, 0, &rr)) {
            DEBUG_debug("ns_paserr returned error ", strerror(errno));
            return false;
        } else {
            if (ns_rr_type(rr) == ns_t_txt) {
                DEBUG_debug("ns_rr_rdlen returned ", ns_rr_rdlen(rr));
                u_char *k = (u_char *)ns_rr_rdata(rr);
                char p[400];
                unsigned int j = 0;
                for (unsigned int j1 = 1; j1 < ns_rr_rdlen(rr); j1++) {
                    p[j++] = k[j1];
                }
//                p[j] = (char)NULL;
                p[j] = '\0';
                DEBUG_debug("ns_rr_data returned ", p );
                String dnstxt(p);
                user = dnstxt.before(",");
                return true;
            }
        }
    }
#endif
    return false;
}

String ConnectionHandler::dns_error(int herror) {

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

bool
ConnectionHandler::gen_error_mess(Socket &peerconn, NaughtyFilter &cm, String &eheader, String &ebody, int mess_no1,
                                  int mess_no2, std::string mess) {
    cm.message_no = mess_no1;
    eheader = "HTTP/1.1 " + mess + "\nContent-Type: text/html\r\nConnection: Close\r\n";
    if(mess_no1 > 0) {
        ebody = "<HTML><HEAD><TITLE>e2guardian - ";
        ebody += mess;
        ebody += "</TITLE></HEAD><BODY><H1>e2guardian - ";
        ebody += mess;
        ebody += "</H1>";
        if (mess_no1 > 0)
            ebody += o.language_list.getTranslation(mess_no1);
        if (mess_no2 > 0)
            ebody += o.language_list.getTranslation(mess_no2);
        ebody += "</BODY></HTML>\r\n";
    }
    return true;
}

bool
ConnectionHandler::writeback_error(NaughtyFilter &cm, Socket &cl_sock, int mess_no1, int mess_no2, std::string mess) {
    String eheader, ebody;
    gen_error_mess(cl_sock, cm, eheader, ebody, mess_no1, mess_no2, mess);
    cl_sock.writeString(eheader.c_str());
    cl_sock.writeString("\r\n");
    cl_sock.writeString(ebody.c_str());
    return true;
}

bool
ConnectionHandler::goMITM(NaughtyFilter &checkme, Socket &proxysock, Socket &peerconn, bool &persistProxy, bool &authed,
                          bool &persistent_authed, String &ip, stat_rec *&dystat, std::string &clientip,
                          bool transparent) {

        DEBUG_debug(" Start goMITM nf ", checkme.isItNaughty, " upfail ", checkme.upfailure);


    DEBUG_debug(" -Intercepting HTTPS connection");
    HTTPHeader *header = checkme.request_header;
    HTTPHeader *docheader = checkme.response_header;
    bool justLog = false;

    //  CA intialisation now Moved into OptionContainer so now done once on start-up
    //  instead of on every request

    X509 *cert = NULL;
    struct ca_serial caser;
    caser.asn = NULL;
    caser.charhex = NULL;
    caser.filepath = NULL;
    caser.filename = NULL;

    EVP_PKEY *pkey = NULL;
    bool certfromcache = false;
    //generate the cert
    DEBUG_debug(" -Getting ssl certificate for client connection");

    pkey = o.cert.ca->getServerPkey();

    //generate the certificate but dont write it to disk (avoid someone
    //requesting lots of places that dont exist causing the disk to fill
    //up / run out of inodes
    certfromcache = o.cert.ca->getServerCertificate(checkme.urldomain.CN().c_str(), &cert,
                                                   &caser, checkme.isiphost);
    if (caser.asn == NULL) {
        DEBUG_debug("caser.asn is NULL");                            }
        //				std::cerr << "serials are: " << (char) *caser.asn << " " < caser.charhex  << std::endl;

        //check that the generated cert is not null and fillin checkme if it is
        if (cert == NULL) {
            checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to get ssl certificate";
            checkme.message_no = 151;
            checkme.whatIsNaughty = o.language_list.getTranslation(151);
            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
            justLog = true;
        } else if (pkey == NULL) {
            checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to load ssl private key";
            checkme.message_no = 153;
            checkme.whatIsNaughty = o.language_list.getTranslation(153);
            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
            justLog = true;
            X509_free(cert);
            cert = NULL;
        }

//startsslserver on the connection to the client
    //if (!checkme.isItNaughty)
    if (true)
    {
        DEBUG_debug(" -Going SSL on the peer connection");

        if (!transparent) {
//send a 200 to the client no matter what because they managed to get a connection to us
//and we can use it for a blockpage if nothing else
            std::string msg = "HTTP/1.1 200 Connection established\r\n\r\n";
            if (!peerconn.writeString(msg.c_str()))
            {
                        peerDiag("Unable to send 200 connection  established to client ", peerconn);
                        if(cert != NULL) {
                            X509_free(cert);
                            cert = NULL;
                        }
                        return false;
            }
        }

        if (peerconn.startSslServer(cert, pkey, o.cert.set_cipher_list) < 0) {
//make sure the ssl stuff is shutdown properly so we display the old ssl blockpage
            peerconn.stopSsl();

            checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to negotiate ssl connection to client";
            checkme.message_no = 154;
            checkme.whatIsNaughty = o.language_list.getTranslation(154);
            checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
            checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
            justLog = true;
            if(cert != NULL) {
                X509_free(cert);
                cert = NULL;
            }

        }
    }

    if (proxysock.isOpen()) {
        // tsslclient connected to the proxy and check the certificate of the server
        DEBUG_debug(" nf ", checkme.isItNaughty, " upfail ", checkme.upfailure);

        if (!checkme.isItNaughty) {
            DEBUG_debug(" -Going SSL on upstream connection ");
            std::string certpath = std::string(o.cert.ssl_certificate_path);
            if (proxysock.startSslClient(certpath, checkme.urldomain)) {
                checkme.isItNaughty = true;
//checkme.whatIsNaughty = "Failed to negotiate ssl connection to server";
                checkme.message_no = 160;
                checkme.whatIsNaughty = o.language_list.getTranslation(160);
                checkme.whatIsNaughtyLog = checkme.whatIsNaughty;
                checkme.whatIsNaughtyCategories = o.language_list.getTranslation(70);
            }
        }
        DEBUG_debug(" nf ", checkme.isItNaughty, " upfail ", checkme.upfailure);

        if (!checkme.isItNaughty) {
            DEBUG_debug(" -Checking certificate");
            //will fill in checkme of its own accord
            if (!checkme.nocheckcert) {
                checkCertificate(checkme.urldomain, &proxysock, &checkme);
                checkme.badcert = checkme.isItNaughty;
            }
        }
    }

    DEBUG_debug(" nf ", checkme.isItNaughty, " upfail ", checkme.upfailure);
    if ((!checkme.isItNaughty) && (!checkme.upfailure)) {
        bool writecert = true;
        if (!certfromcache) {
            writecert = o.cert.ca->writeCertificate(checkme.urldomain.c_str(), cert,
                                               &caser);
        }

        //if we cant write the certificate its not the end of the world but it is slow
        if (!writecert) {
            E2LOGGER_error("Couldn't save certificate to on disk cache");
        }
        DEBUG_debug(" -Handling connections inside ssl tunnel");

        if (authed) {
            persistent_authed = true;
        }

        //handleConnection inside the ssl tunnel
        handleConnection(peerconn, ip, true, proxysock, dystat);
        DEBUG_debug(" -Handling connections inside ssl tunnel: done");
    }
    o.cert.ca->free_ca_serial(&caser);

//stopssl on the proxy connection
//if it was marked as naughty then show a deny page and close the connection
    if (checkme.isItNaughty || checkme.upfailure) {
        DEBUG_debug(" -SSL Interception failed ", checkme.whatIsNaughty, " nf ", checkme.isItNaughty, " upfail ", checkme.upfailure);

        doLog(clientuser, clientip, checkme);

        if(!justLog)
        	denyAccess(&peerconn, &proxysock, header, docheader, &checkme.logurl, &checkme, &clientuser,
                   &clientip, filtergroup, checkme.ispostblock, checkme.headersent, checkme.wasinfected,
                   checkme.scanerror, checkme.badcert);
    }
    DEBUG_debug(" -Shutting down ssl to proxy");
    proxysock.stopSsl();

    DEBUG_debug(" -Shutting down ssl to client");

    peerconn.stopSsl();

//tidy up key and cert
    if(cert != NULL) {
        X509_free(cert);
        cert = NULL;
    }
    if(pkey != NULL) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    persistProxy = false;
    proxysock.close();

    return true;
}

bool ConnectionHandler::doAuth(int &auth_result, bool &authed, int &filtergroup, AuthPlugin *auth_plugin, Socket &peerconn,
                          HTTPHeader &header, NaughtyFilter &cm, bool only_client_ip, bool isconnect_like) {
    Socket nullsock;
    return doAuth(auth_result, authed, filtergroup, auth_plugin, peerconn, nullsock, header, cm, only_client_ip, isconnect_like);
}

bool ConnectionHandler::doAuth(int &rc, bool &authed, int &filtergroup, AuthPlugin *auth_plugin, Socket &peerconn,
                               Socket &proxysock, HTTPHeader &header, NaughtyFilter &cm, bool only_client_ip, bool isconnect_like) {

    DEBUG_debug(" -Not got persistent credentials for this connection - querying auth plugins");
    bool dobreak = false;
    rc = 0;
    if (o.plugins.authplugins.size() != 0) {
        // We have some auth plugins load
       // int authloop = 0;
        rc = 0;
        String tmp;
        int p = peerconn.getPort();

        for (std::deque<Plugin *>::iterator i = o.plugins.authplugins_begin; i != o.plugins.authplugins_end; i++) {
            DEBUG_debug(" -Querying next auth plugin...");
            // try to get the username & parse the return value
            auth_plugin = (AuthPlugin *) (*i);
            if ((only_client_ip && !auth_plugin->client_ip_based) || !auth_plugin->port_matched(p))
                continue;

            // auth plugin selection for multi ports
            //
            //
            // Logic changed to allow auth scan with multiple ports as option to replace auth-port
            //       fixed mapping
            //

                rc = auth_plugin->identify(peerconn, proxysock, header, clientuser, is_real_user, SBauth, cm);

            if (rc == E2AUTH_NOMATCH) {
                DEBUG_auth("Auth plugin did not find a match; querying remaining plugins");
                continue;
            } else if (rc == E2AUTH_REDIRECT) {
                DEBUG_auth("Auth plugin told us to redirect client to \"", clientuser, "\"; not querying remaining plugins");
                if (isconnect_like)      // it is connect or trans https so cannot send redirect
                {
                    dobreak = true;
                    break;
                } else {
                    // ident plugin told us to redirect to a login page
                    String writestring("HTTP/1.1 302 Redirect\r\nLocation: ");
                    writestring += clientuser;
                    writestring += "\r\n\r\n";
                    peerconn.writeString(writestring.toCharArray());   // no action on failure
                    dobreak = true;
                    break;
                }
            } else if (rc == E2AUTH_OK_NOPERSIST) {
                DEBUG_auth("Auth plugin  returned OK but no persist not setting persist auth");
                overide_persist = true;
            } else if (rc == E2AUTH_OK_GOT_GROUP)  {
                DEBUG_auth("Auth plugin  returned OK_GOT_GROUP ");
                filtergroup = SBauth.filter_group;
                authed = true;
                break;      // got user and group so break
            } else if (rc == E2AUTH_OK_GOT_GROUP_NAME)  {
                DEBUG_auth("Auth plugin  returned OK_GOT_GROUP_NAME ");
                filtergroup = ldl->getFgFromName(SBauth.fg_name);
                if (filtergroup > -1) {
                    SBauth.filter_group = filtergroup;
                    authed = true;
                    break;      // got user and group so break
                } else {
                    rc = E2AUTH_OK;  // just got user so change status flag to that effect
                }
            } else if (rc == E2AUTH_407_SENT)  {
                DEBUG_auth("Auth plugin  has sent 407 so break");
                dobreak = true;
                break;
            } else if (rc < 0) {
                E2LOGGER_error("Auth plugin returned error code: ", rc);
                dobreak = true;
                break;
            }
            DEBUG_auth(" -Auth plugin found username ", clientuser, " (", oldclientuser, "), now determining group");

            if (clientuser == oldclientuser) {
                DEBUG_auth(" -Same user as last time, re-using old group no.");
                authed = true;
                filtergroup = oldfg;
                break;
            }
            // try to get the filter group & parse the return value
            rc = auth_plugin->determineGroup(clientuser, filtergroup, ldl->StoryA, cm);
            if (rc == E2AUTH_OK) {
                DEBUG_auth("Auth plugin found username & group; not querying remaining plugins");
                authed = true;
                break;
            } else if (rc == E2AUTH_NOMATCH) {
                DEBUG_auth("Auth plugin did not find a match; querying remaining plugins");
                clientuser = "";
                continue;
            } else if (rc == E2AUTH_NOGROUP) {
                if (o.plugins.auth.auth_requires_user_and_group || !is_real_user) {
                    clientuser = "";
                    SBauth.user_source = "";
                    continue;
                }
                DEBUG_auth("Auth plugin found username \"", clientuser, "\" but no associated group; not querying remaining plugins");

                authed = true;
                break;
            } else if (rc < 0) {
                E2LOGGER_error("Auth plugin returned error code: ", rc);
                dobreak = true;
                break;
            }
        } // end of querying all plugins (for)

        // break the peer loop
        if (dobreak)
            return false;
        //break;

        if ((!authed) || (filtergroup < 0) || (filtergroup >= o.filter.numfg)) {
#ifdef DEBUG_LOW
            if (!authed) {
                DEBUG_auth(" -No identity found; using defaults");
            }
            else {
                DEBUG_auth(" -Plugin returned out-of-range filter group number; using defaults");
            }
#endif

            // If none of the auth plugins currently loaded rely on querying the proxy,
            // such as 'ident' or 'ip', then pretend we're authed. What this flag
            // actually controls is whether or not the query should be forwarded to the
            // proxy (without pre-emptive blocking); we don't want this for 'ident' or
            // 'ip', because Squid isn't necessarily going to return 'auth required'.
            // All proxy-auths have been removed in v5.5 so set this to 'true'
            authed =  true;
            clientuser = "-";
        } else {
            DEBUG_auth(" -Identity found; caching username & group");
            if (auth_plugin->is_connection_based && !overide_persist) {
                DEBUG_auth("Auth plugin is for a connection-based auth method - keeping credentials for entire connection");
                persistent_authed = true;
            }
            oldclientuser = clientuser;
            oldfg = filtergroup;
        }
    } else {
        // We don't have any auth plugins loaded
        DEBUG_auth(" -No auth plugins loaded; using defaults & feigning persistency");
        authed = true;
        clientuser = "-";
        //filtergroup = 0; //default group - one day configurable? - default now set before call to doAuth
        persistent_authed = true;
    }
    return true;
}

bool ConnectionHandler::checkByPass(NaughtyFilter &checkme, std::shared_ptr<LOptionContainer> &ldl, HTTPHeader &header,
                                    Socket &proxysock, Socket &peerconn, std::string &clientip) {

    //first check if bypass allowed and set isbypassallowed
    checkme.isbypassallowed = (ldl->fg[filtergroup]->bypass_mode != 0);
    checkme.isinfectionbypassallowed = (ldl->fg[filtergroup]->infection_bypass_mode != 0);
    checkme.isscanbypassallowed = (ldl->fg[filtergroup]->scan_bypass);
//    if (!(checkme.isbypassallowed || checkme.isinfectionbypassallowed || checkme.isscanbypassallowed))
//        return false;

    if ((checkme.url).contains("BYPASS=") && ((checkme.url).length() > 45))  // may be url by-pass
    {
        // int bypasstimestamp = 0;
        if (checkme.isscanbypassallowed &&
            isScanBypassURL(checkme.url, ldl->fg[filtergroup]->magic.c_str(), clientip.c_str())) {
            DEBUG_debug(" -Scan Bypass URL match");
            checkme.isscanbypass = true;
            checkme.isbypass = true;
            checkme.message_no = 608;
            checkme.log_message_no = 608;
            checkme.exceptionreason = o.language_list.getTranslation(608);
            //we need to decode the URL and send the temp file with the
            //correct header to the client then delete the temp file
            checkme.tempfilename = (checkme.url.after("GSBYPASS=").after("&N="));
            checkme.tempfilemime = (checkme.tempfilename.after("&M="));
            checkme.tempfiledis = (header.decode(checkme.tempfilemime.after("&D="), true));
            DEBUG_debug(" -Original filename: ", checkme.tempfiledis);
            String rtype(header.requestType());
            checkme.tempfilemime = checkme.tempfilemime.before("&D=");
            checkme.tempfilename = o.content.download_dir + "/tf" + checkme.tempfilename.before("&M=");
            return true;
        }
        DEBUG_debug(" -About to check for bypass...");
        if (checkme.isscanbypass) {
            checkme.bypasstimestamp = isBypassURL(checkme.logurl, ldl->fg[filtergroup]->magic.c_str(),
                                                  clientip.c_str(), "GBYPASS=", clientuser);
            if (checkme.bypasstimestamp > 0) {
                header.chopBypass(checkme.logurl, "GBYPASS=");
                if (checkme.bypasstimestamp > 1) {
                    checkme.exceptionreason = o.language_list.getTranslation(606);
                    checkme.message_no = 606;
                }
                DEBUG_debug(" -Filter bypass URL match");
            }
        }

        if ((checkme.bypasstimestamp == 0) && (checkme.isinfectionbypassallowed)) {
            checkme.bypasstimestamp = isBypassURL(checkme.logurl, ldl->fg[filtergroup]->imagic.c_str(),
                                                  clientip.c_str(), "GIBYPASS=", clientuser);
            if (checkme.bypasstimestamp > 0) {
                header.chopBypass(checkme.logurl, "GIBYPASS=");
                if (checkme.bypasstimestamp > 1) {
                    checkme.exceptionreason = o.language_list.getTranslation(608);
                    checkme.message_no = 608;
                }
                DEBUG_debug(" -Infection bypass URL match");
            }
        }

        if ((checkme.bypasstimestamp == 0) && (checkme.istoobigbypassallowed)) {
            checkme.bypasstimestamp = isBypassURL(checkme.logurl, ldl->fg[filtergroup]->magic.c_str(),
                                                  clientip.c_str(), "GOSBYPASS=", clientuser);
            if (checkme.bypasstimestamp > 0) {
                header.chopBypass(checkme.logurl, "GOSBYPASS=");
                if (checkme.bypasstimestamp > 1) {
                    checkme.exceptionreason = o.language_list.getTranslation(608);
                    checkme.message_no = 608;
                }
                DEBUG_debug(" -Too big to scan bypass URL match");
            }
        }
    }

    if (checkme.bypasstimestamp > 0) {
        if (checkme.bypasstimestamp > 1) { // not expired
            checkme.isbypass = true;
            checkme.isexception = true;
            checkme.log_message_no = checkme.message_no;
        }
    } else if (checkme.isbypassallowed) {  // no bypass in url so check for by pass cookie
        String ud(checkme.urldomain);
        if (ud.startsWith("www.")) {
            ud = ud.after("www.");
        }
        if (header.isBypassCookie(ud, ldl->fg[filtergroup]->cookie_magic.c_str(),
                                    clientip.c_str(), clientuser.c_str())) {
            DEBUG_debug(" -Bypass cookie match");
            checkme.iscookiebypass = true;
            checkme.isbypass = true;
            checkme.isexception = true;
            checkme.exceptionreason = o.language_list.getTranslation(607);
        }
    }
    DEBUG_debug(" -Finished bypass checks.");

    if (checkme.isbypass) {
        DEBUG_debug(" -bypass activated!");
    }
    //
    // End of bypass
    //
    return false;    // checkme.isbypass should be checked for success - only returns true if is a scanned by-pass
}

bool ConnectionHandler::sendScanFile(Socket &peerconn, NaughtyFilter &checkme, bool is_icap, ICAPHeader *icaphead) {
    try {
        checkme.docsize = sendFile(&peerconn, checkme, checkme.url, is_icap, icaphead);
        checkme.request_header->chopBypass(checkme.url,"GSBYPASS=");
        checkme.logurl = checkme.request_header->getLogUrl();

        doLog(clientuser, checkme.clientip, checkme);

        if (o.content.delete_downloaded_temp_files) {
            unlink(checkme.tempfilename.toCharArray());
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
                   (ldl->fg[filtergroup]->searchterm_flag ? ldl->fg[filtergroup]->searchterm_list
                                                          : ldl->fg[filtergroup]->banned_phrase_list),
                   ldl->fg[filtergroup]->searchterm_limit, true);
        if (cm.isItNaughty) {
            cm.blocktype = 2;
        }
    }
    return;
}

void ConnectionHandler::check_content(NaughtyFilter &cm, DataBuffer &docbody, Socket &proxysock, Socket &peerconn,
                                      std::deque<CSPlugin *> &responsescanners) {
    if (((cm.response_header->isContentType("text", ldl->fg[filtergroup]) ||
          cm.response_header->isContentType("-", ldl->fg[filtergroup])) && !cm.isexception) ||
        !responsescanners.empty()) {
        cm.waschecked = true;
        if (!responsescanners.empty()) {
            DEBUG_debug(" -Filtering with expectation of a possible csmessage");;
            String csmessage;
            contentFilter(cm.response_header, cm.request_header, &docbody, &proxysock, &peerconn, &cm.headersent,
                          &cm.pausedtoobig,
                          &cm.docsize, &cm, cm.wasclean, filtergroup, responsescanners, &clientuser, &cm.clientip,
                          &cm.wasinfected, &cm.wasscanned, cm.isbypass, cm.urld, cm.urldomain, &cm.scanerror,
                          cm.contentmodified, &csmessage);
            if (csmessage.length() > 0) {
                DEBUG_debug(" -csmessage found: ", csmessage);;
                cm.exceptionreason = csmessage.toCharArray();
            }
        } else {
            DEBUG_debug(" -Calling contentFilter ");;
            contentFilter(cm.response_header, cm.request_header, &docbody, &proxysock, &peerconn, &cm.headersent,
                          &cm.pausedtoobig,
                          &cm.docsize, &cm, cm.wasclean, filtergroup, responsescanners, &clientuser, &cm.clientip,
                          &cm.wasinfected, &cm.wasscanned, cm.isbypass, cm.urld, cm.urldomain, &cm.scanerror,
                          cm.contentmodified, NULL);
        }
    } else {
        cm.tunnel_rest = true;
    }
    DEBUG_debug("End content check isitNaughty is  ", cm.isItNaughty);
}

int ConnectionHandler::handleProxyTLSConnection(Socket &peerconn, String &ip, Socket &upsconn, stat_rec* &dystat) {

    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    peerconn.setTimeout(o.net.pcon_timeout);

    X509 *cert = NULL;
    struct ca_serial caser;
    caser.asn = NULL;
    caser.charhex = NULL;
    caser.filepath = NULL;
    caser.filename = NULL;

    EVP_PKEY *pkey = NULL;
    bool certfromcache = false;
    //generate the cert
    DEBUG_debug(" -Getting ssl certificate for client TLS proxy connection");

    pkey = o.cert.ca->getServerPkey();

    //generate the certificate but dont write it to disk (avoid someone
    //requesting lots of places that dont exist causing the disk to fill
    //up / run out of inodes
    certfromcache = o.cert.ca->getServerCertificate(o.net.TLSproxyCN.c_str(), &cert,
                                               &caser, o.net.TLSproxyCN_is_ip);
    if (caser.asn == NULL) {
        DEBUG_debug("caser.asn is NULL");                            }
        //				std::cerr << "serials are: " << (char) *caser.asn << " " < caser.charhex  << std::endl;

        //check that the generated cert is not null
        if (cert == NULL) {
            DEBUG_debug(" cert is NULL for TLS proxy");
            return 1;
        }

        if (peerconn.startSslServer(cert, pkey, o.cert.set_cipher_list) < 0) {
            peerconn.stopSsl();
            if(cert != NULL) {
                X509_free(cert);
                cert = NULL;
            }
            return 1;
        }

        if(!certfromcache)
            o.cert.ca->writeCertificate(o.net.TLSproxyCN.c_str(), cert, &caser);

        // Now create a pipe - push one end onto normal proxy queue and then tunnel between other end and the ssled peerconn
        int socks[2];
    //if (socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK, 0, socks) != 0)
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks) != 0) {
        E2LOGGER_error("Unable to create socket pair");
        return 1;
    }
    Socket *s_inside = new Socket(socks[0]);
        Socket s_outside(socks[1]);
        s_inside->setClientAddr(peerconn.getPeerIP(),peerconn.getPeerSourcePort());
        s_inside->setPort(peerconn.getPort());
        s_inside->down_thread_id = thread_id;

        //Q for service
        LQ_rec lq_rec;
        lq_rec.sock = s_inside;
        lq_rec.ct_type = CT_PROXY;
    DEBUG_debug("inside pair socket about to push to Q");
        o.http_worker_Q.push(lq_rec);
        DEBUG_debug("inside pair socket pushed to Q");
//DEBUG_network("about to connect to 8084");
//    upsconn.connect("127.0.0.1", 8084);
//    DEBUG_network("connected to 8084 - starting tunnell");

        // and then two way tunnel to outside socket;
        FDTunnel tunn;

        tunn.tunnel(peerconn, s_outside, true);
    DEBUG_network("tunnell finished");
        peerconn.stopSsl();
        peerconn.close();
       // if (s_inside != nullptr) delete s_inside;
        return 0;
    }

    int ConnectionHandler::handleTHTTPSConnection(Socket &peerconn, String &ip, Socket &proxysock, stat_rec* &dystat) {
        DEBUG_trace("");

        struct timeval thestart;
        gettimeofday(&thestart, NULL);

        peerconn.setTimeout(o.net.pcon_timeout);

        HTTPHeader docheader(__HEADER_RESPONSE); // to hold the returned page header from proxy
        HTTPHeader header(__HEADER_REQUEST); // to hold the incoming client request headeri(ldl)

        NaughtyFilter checkme(header, docheader, SBauth);
        checkme.listen_port = peerconn.getPort();
        checkme.reset();


        std::string clientip(ip.toCharArray()); // hold the clients ip
        docheader.setClientIP(ip);

        if (clienthost) delete clienthost;

        clienthost = NULL; // and the hostname, if available
        matchedip = false;


        DEBUG_thttps(" -got peer connection - clientip is ", clientip);

        try {
            int rc;


            //int oldfg = 0;
            bool authed = false;
            bool isbanneduser = false;
            bool firsttime = true;

            AuthPlugin *auth_plugin = NULL;

            // RFC states that connections are persistent
            //bool persistOutgoing = true;
            //bool persistPeer = true;
            bool persistProxy = false;
            //bool direct = false;

            char buff[2048];
            rc = peerconn.readFromSocket(buff, 5, (MSG_PEEK ), 20000, true);
            DEBUG_thttps( "bytes peeked ", rc );
            unsigned short toread = 0;
            if (rc == 5) {
            if (buff[0] == 22 && buff[1] == 3 && buff[2] > 0 && buff[2] < 4 )   // has TLS hello signiture
            checkme.isTLS = true;

        toread = ( buff[3] << (8*1) | buff[4]);
        if (toread > 2048) toread = 2048;
        }

        DEBUG_thttps("hello length is ", toread, " magic is ", buff[0], buff[1], buff[2], " isTLS is ", checkme.isTLS);

       if(checkme.isTLS) {
            rc = peerconn.readFromSocket(buff, toread, (MSG_PEEK ), 10000);
            if (rc < 1 ) {     // get header from client, allowing persistency
                if (o.conn.logconerror) {
                    if (peerconn.getFD() > -1) {

                        int err = peerconn.getErrno();
                        //int pport = peerconn.getPeerSourcePort();
                        std::string peerIP = peerconn.getPeerIP();
                        if(peerconn.isTimedout())
                        {
                            DEBUG_thttps("Connection timed out");
                        }
                        E2LOGGER_error("No header recd from client - errno: ", err);
                    } else {
                        E2LOGGER_info("Client connection closed early - no TLS header received");
                    }
                }
            firsttime = false;
            //persistPeer = false;
        } else {
            DEBUG_thttps("bytes peeked ", rc );
             char *ret = get_TLS_SNI(buff, &rc);
             if (ret != NULL) {
             checkme.url = ret;
             checkme.hasSNI = true;
             }

            ++dystat->reqs;
        }
        }

        get_original_ip_port(peerconn,checkme);

        if(!checkme.hasSNI) {
            if(checkme.got_orig_ip) checkme.url = checkme.orig_ip;
            else // no SNI and no orig_ip - so can't do anything sensible
            return -1;
        }

        DEBUG_thttps("hasSNI = ", checkme.hasSNI, " SNI is ", checkme.url,  " Orig IP ", checkme.orig_ip, " Orig port ", checkme.orig_port );
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
            checkme.nomitm = false;
            gettimeofday(&checkme.thestart, NULL);


            // Look up reverse DNS name of client if needed
            if (o.conn.reverse_client_ip_lookups) {
                getClientFromIP(clientip.c_str(), checkme.clienthost);
            }

            filtergroup = o.filter.default_trans_fg;

            //if(o.log_requests) {
            if (e2logger.isEnabled(LoggerSource::requestlog)) {
                std::string fnt = "THTTPS";
                doRQLog(clientuser, clientip, checkme, fnt);
            }

            checkme.clientip = clientip;

            //CALL SB pre-authcheck
            ldl->StoryA.runFunctEntry(ENT_STORYA_PRE_AUTH_THTTPS,checkme);
            DEBUG_thttps("After StoryA thttps-pre-authcheck", checkme.isexception, " mess_no ",  checkme.message_no );
            checkme.isItNaughty = checkme.isBlocked;
            bool isbannedip = checkme.isBlocked;

            //
            //
            // Start of Authentication Checks
            //
            //
            // don't have credentials for this connection yet? get some!
            overide_persist = false;
            if(!(checkme.isItNaughty || checkme.isexception)) {
                if (!doAuth(checkme.auth_result, authed, filtergroup, auth_plugin,  peerconn, proxysock,  header, checkme, true, true))
                {

                    if((checkme.auth_result == E2AUTH_REDIRECT) && ldl->fg[filtergroup]->ssl_mitm)
                    {
                       if(!checkme.nomitm)checkme.gomitm = true;
                       checkme.isdone = true;
                    } else {
                       break;
                    }
                 }
            }
            checkme.filtergroup = filtergroup;
            if(!checkme.nomitm) checkme.nomitm = !ldl->fg[filtergroup]->ssl_mitm;

            DEBUG_thttps(" -username: ", clientuser, " -filtergroup: ", filtergroup);
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


            if(checkme.hasSNI & !checkme.nomitm ) checkme.ismitmcandidate = ldl->fg[filtergroup]->ssl_mitm;
            if(checkme.ismitmcandidate) {
                checkme.automitm = ldl->fg[filtergroup]->automitm;
            }


            // TODO restore this for THTTPS ??
            //if (isbannedip) {
               // matchedip = clienthost == NULL;
            //} else {
            // /   if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
            // /                   checkme.urld)) {
            // /       DEBUG_thttps(" isbannedip = ", isbannedip, "ispart_banned = ", part_banned, " isexception = ", checkme.isexception);
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

            //
            // Start of exception checking
            //
            // being a banned user/IP overrides the fact that a site may be in the exception lists
            // needn't check these lists in bypass modes
            if (!(checkme.isdone || isbanneduser || isbannedip || checkme.isexception)) {
                DEBUG_trace("Check StoryB thttps-checkrequest");
                ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_THTTPS_REQUEST,checkme);
                DEBUG_trace("After StoryB thttps-checkrequest",
                            " isException: ", String(checkme.isexception),
                            " mess_no ", String(checkme.message_no));

		        if (ldl->fg[filtergroup]->reporting_level != -1){
                	checkme.isItNaughty = checkme.isBlocked;
		        } else {
			        checkme.isItNaughty = false;
		            checkme.isBlocked = false;
		        }
            }

            //now send upstream and get response
            if (!checkme.isItNaughty && !persistProxy) {
                int out_port;
                if(checkme.got_orig_ip && o.conn.use_original_ip_port)
                    out_port = checkme.orig_port;
                else
                    out_port = 443;

                if (connectUpstream(proxysock, checkme,out_port) > -1) {
                    if(!checkme.isdirect) {
                        if (sendProxyConnect(checkme.connect_site,&proxysock, &checkme) != 0) {
                       checkme.upfailure = true;
                       proxysock.close();
                       }
                    }
                } else {
                       checkme.upfailure = true;
                }
            }

            DEBUG_thttps(" after connectUpstream nf ", checkme.isItNaughty," upfail ", checkme.upfailure);

            if((checkme.isItNaughty ||checkme.upfailure) && checkme.automitm && checkme.hasSNI)
                checkme.gomitm = true;  // allows us to send splash page

            if (checkme.isexception && !checkme.upfailure) {
                    checkme.tunnel_rest = true;
             } else {

            //if ismitm - GO MITM
                if (checkme.gomitm && !checkme.nomitm)
                {
                DEBUG_thttps("Going MITM ....");
                if(!ldl->fg[filtergroup]->mitm_check_cert)
                    checkme.nocheckcert = true;
                goMITM(checkme, proxysock, peerconn, persistProxy, authed, persistent_authed, ip, dystat, clientip, true);
                //persistPeer = false;
                persistProxy = false;
                //if (!checkme.isItNaughty)
                    break;
                } else {
                if (!checkme.upfailure)
                    checkme.tunnel_rest = true;
                }
            }

            //if not grey tunnel response
            if (!checkme.isItNaughty && checkme.tunnel_rest) {
                DEBUG_thttps(" -Tunnelling to client");
                if (!fdt.tunnel(proxysock, peerconn,true, -1 , true))
                    persistProxy = false;
                checkme.docsize += fdt.throughput;
            }

            // it is not possible to send splash page on Thttps without MITM so do not try!

            //Log
            if (!checkme.isourwebserver) { // don't log requests to the web server
                doLog(clientuser, clientip, checkme);
            }


                proxysock.close(); // close connection to proxy


        }
        } catch (std::exception & e)
        {
        DEBUG_thttps(" - THTTPS connection handler caught an exception: ", e.what() );
        if(o.conn.logconerror)
            E2LOGGER_error(" - THTTPS connection handler caught an exception %s" , e.what());

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


bool ConnectionHandler::get_original_ip_port(Socket &peerconn, NaughtyFilter &checkme)
{   // get original IP destination & port
#ifdef SOL_IP       // linux
#define SO_ORIGINAL_DST 80
    sockaddr_in origaddr;
    socklen_t origaddrlen(sizeof(sockaddr_in));
    if (
getsockopt(peerconn.getFD(), SOL_IP, SO_ORIGINAL_DST, &origaddr, &origaddrlen ) < 0
            ) {
        E2LOGGER_error("Failed to get client's original destination IP: ", strerror(errno));
        return false;
    } else {
        char res[INET_ADDRSTRLEN];
        checkme.orig_ip = inet_ntop(AF_INET,&origaddr.sin_addr,res,sizeof(res));
        // if orig_ip == one of our box ip's it is not true transparent so return false so that dns lookup is enabled
        if (o.net.check_ip.size() > 0) {
            for (auto it = o.net.check_ip.begin(); it != o.net.check_ip.end(); it++) {
                if (*it == checkme.orig_ip) {
                    checkme.orig_ip = "";
                    return false;
                }
            }
        }
        checkme.orig_port = ntohs(origaddr.sin_port);
        checkme.got_orig_ip = true;
        return true;
    }
#else   // TODO: BSD code needs adding - depends on firewall being used
        // assign checkme.orig_ip and checkme.orig_port and return true
        // or return false on error

        // return false until BSD code added
        return false;
#endif
}


int ConnectionHandler::handleICAPConnection(Socket &peerconn, String &ip, Socket &proxysock, stat_rec *&dystat) {

#ifdef DEBUG_HIGH
    int pcount = 0;
#else
#ifdef DEBUG_LOW
    int pcount = 0;
#endif
#endif

    bool ismitm = false;

    struct timeval thestart;
    gettimeofday(&thestart, NULL);

    peerconn.setTimeout(o.net.pcon_timeout);

    std::string clientip(ip.toCharArray()); // hold the ICAP clients ip

    if (clienthost) delete clienthost;

    clienthost = NULL; // and the hostname, if available
    matchedip = false;

    //try {
        //int rc;
        //bool authed = false;
        bool firsttime = true;
        //bool isbanneduser = true;

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

            NaughtyFilter checkme(icaphead.HTTPrequest, icaphead.HTTPresponse, SBauth);
            checkme.listen_port = peerconn.getPort();
            DataBuffer docbody;
            docbody.setTimeout(o.net.exchange_timeout);
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
                DEBUG_icap(" ICAP -persisting (count ", ++pcount, ")", " Client IP: ", clientip);

                icaphead.reset();
                if (!icaphead.in(&peerconn, true)) {
                    if (peerconn.isTimedout()) {
                        DEBUG_icap( " -ICAP Persistent connection timed out");
                        //send error response
                        wline = "ICAP/1.0 408 Request timeout\r\n";
                        wline += "Service: ";
        			    wline += PACKAGE_STRING; 
		        	    wline  += "\r\n";
                        wline += "Encapsulated: null-body=0\r\n";
                        wline += "\r\n";
                        peerconn.writeString(wline.toCharArray());
                    } else {

                        DEBUG_icap( " -ICAP Persistent connection closed");
                        // TODO: send error reply if needed
                        break;
                    }
                }
                ++dystat->reqs;

                ip = icaphead.clientip;
                checkme.clientip = ip;

                // we will actually need to do *lots* of resetting of flags etc. here for pconns to work
                gettimeofday(&thestart, NULL);
                checkme.thestart = thestart;

                //authed = false;
                //isbanneduser = false;

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
                DEBUG_icap("service options enabled : ", wline,
                                    " icaphead.service_reqmod: ", icaphead.service_reqmod,
                                    " icaphead.service_resmod: ", icaphead.service_resmod,
                                    " icaphead.service_options: ",
                                    " icaphead.icap_reqmod_service: ", icaphead.icap_reqmod_service,
                                    " icaphead.icap_resmod_service: ", icaphead.icap_resmod_service,
                                    " icaphead.icap_reqmod_service: ", icaphead.icap_reqmod_service);

            // Check service option REQMOD, RESMOD, OPTIONS and call apropreate function(s)
            //
            if (icaphead.service_reqmod && icaphead.icap_reqmod_service) {
                DEBUG_icap( "Icap reqmod check ");
                if (handleICAPreqmod(peerconn,ip, checkme, icaphead, auth_plugin) == 0){
                    continue;
                }else{
                    break;
                }

            } else if (icaphead.service_resmod && icaphead.icap_resmod_service) {
                DEBUG_icap("Icap resmod check ");
                if (handleICAPresmod(peerconn,ip, checkme, icaphead, docbody) == 0)
                    continue;
                else
                   break;
            } else if (icaphead.service_options && icaphead.icap_reqmod_service) {
                // respond with option response
                wline = "ICAP/1.0 200 OK\r\n";
                wline += "Methods: REQMOD\r\n";
                wline += "Service: ";
		        wline += PACKAGE_STRING; 
		        wline  += "\r\n";
                wline += "ISTag: \"";
                wline += ldl->ISTag();
                wline += "\"\r\n";
                wline += "Encapsulated: null-body=0\r\n";
                wline += "Allow: 204\r\n";
                //   wline += "Preview: 0\r\n";
                wline += "\r\n";
                peerconn.writeString(wline.toCharArray());
                DEBUG_icap("respmod service options response : ", wline);

            } else if (icaphead.service_options && icaphead.icap_resmod_service) {
               // respond with option response
                wline = "ICAP/1.0 200 OK\r\n";
                wline += "Methods: RESPMOD\r\n";
                wline += "Service: ";
		        wline += PACKAGE_STRING; 
		        wline  += "\r\n";
                wline += "ISTag:";
                wline += ldl->ISTag();
                wline += "\r\n";
                wline += "Encapsulated: null-body=0\r\n";
                wline += "Allow: 204\r\n";
                //   wline += "Preview: 0\r\n";
                wline += "\r\n";
                peerconn.writeString(wline.toCharArray());
                DEBUG_icap("respmod service options response : ", wline);

            } else if ((icaphead.service_reqmod && !icaphead.icap_reqmod_service) ||
                (icaphead.service_resmod && !icaphead.icap_resmod_service)) {
                wline = "ICAP/1.0 405 Method not allowed for service\r\n";
                wline += "Service: ";
		        wline += PACKAGE_STRING; 
		        wline  += "\r\n";
                wline += "Encapsulated: null-body=0\r\n";
                wline += "\r\n";
                peerconn.writeString(wline.toCharArray());
                DEBUG_icap("ICAP/1.0 405 Method not allowed for service ", wline);

           } else {
                //send error response
                wline = "ICAP/1.0 400 Bad request\r\n";
                wline += "Service: ";
		        wline += PACKAGE_STRING; 
		        wline  += "\r\n";
                peerconn.writeString(wline.toCharArray());
                DEBUG_icap("ICAP/1.0 400 Bad request : ", wline);
            }
        }
    //    } //catch (std::exception & e)

    if (!ismitm)
        try {
            DEBUG_icap("ICAP -Attempting graceful connection close");

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
            DEBUG_icap(" -ICAP connection handler caught an exception on connection closedown: ", e.what());
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


    //
    //
    // Start of Authentication Checks
    //
    //
    // don't have credentials for this connection yet? get some!
    overide_persist = false;
    filtergroup = o.filter.default_icap_fg;
    DEBUG_icap("filtergroup set to ICAP default ", filtergroup);
    clientuser = icaphead.username;

    //if(o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        std::string fnt = "REQMOD";
        doRQLog(clientuser, clientip, checkme, fnt);
    }

    int rc = E2AUTH_NOUSER;
    if (!(clientuser.empty() || clientuser == "-")) {
        SBauth.user_name = clientuser;
        SBauth.user_source = "icaph";
        rc = determineGroup(clientuser, filtergroup, ldl->StoryA, checkme, ENT_STORYA_AUTH_ICAP);
        DEBUG_icap("filter group set from filtergroupslist: ", clientuser, " ICAP -filtergroup: ", filtergroup);
    } else {
        oldclientuser = "user not known";
    }

    if (rc != E2AUTH_OK)
    {
        DEBUG_icap("filter group NOT set from filtergroupslist: trying auth plugins");
        persistent_authed = false;
        if (!doAuth(checkme.auth_result, authed, filtergroup, auth_plugin, peerconn, icaphead.HTTPrequest, checkme, true,
                    true)) {
            DEBUG_icap("error return from doAuth");
            //break;  // TODO Error return????
        } else {
            DEBUG_icap("OK return from doAuth");
        }
        if (!(icaphead.username.empty() || icaphead.username == "-")) {
            checkme.user = icaphead.username;      // restore username if we had one from icap header
            clientuser = icaphead.username;      // restore username if we had one from icap header
        }
    }

    authed = true;
    checkme.filtergroup = filtergroup;

    //int unrealgroup = filtergroup+1;
    DEBUG_icap("-username: ", clientuser, " ICAP -filtergroup: ", filtergroup);

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
    if (o.conn.reverse_client_ip_lookups) {
        getClientFromIP(clientip.c_str(),checkme.clienthost);
        //     std::unique_ptr<std::deque<String> > hostnames;
        //     hostnames.reset(ipToHostname(clientip.c_str()));
        //     checkme.clienthost = std::string(hostnames->front().toCharArray());
    }

    //CALL SB pre-authcheck
    ldl->StoryA.runFunctEntry(ENT_STORYA_PRE_AUTH_ICAP, checkme);
    DEBUG_debug("After StoryA icap-pre-authcheck", checkme.isexception, " mess_no ", checkme.message_no);
    checkme.isItNaughty = checkme.isBlocked;
    bool isbannedip = checkme.isBlocked;
    //bool part_banned;
    if (isbannedip) {
        // matchedip = clienthost == NULL;
    } else {
#ifdef NOTDEF      // TODO does this need restoring???
        if (ldl->inRoom(clientip, room, clienthost, &isbannedip, &part_banned, &checkme.isexception,
                        checkme.urld)) {
            DEBUG_debug("ICAP isbannedip = ", isbannedip, "ispart_banned = ", part_banned, " isexception = ", checkme.isexception);
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
    if (!checkme.is_ssl) {

        if (checkByPass(checkme, ldl, icaphead.HTTPrequest, peerconn, peerconn, clientip)
            && sendScanFile(peerconn, checkme, true, &icaphead)) {
            return 0;      // returns only when Scanfile sent. Sets checkme.isbypass if it is a bypass.
        }
    }
    //
    // End of scan by pass
    //

    bool done = false;

    //
    // Start of exception checking
    //
    // being a banned user/IP overrides the fact that a site may be in the exception lists
    // needn't check these lists in bypass modes
    if (!(isbanneduser || isbannedip || checkme.isexception)) {
// Main checking is now done in Storyboard function(s)
        ldl->fg[filtergroup]->StoryB.runFunctEntry(ENT_STORYB_ICAP_REQMOD, checkme);
        DEBUG_debug("After StoryB checkreqmod", checkme.isexception, " mess_no ",  checkme.message_no,
                    " allow_204 : ", icaphead.allow_204);

	if (ldl->fg[filtergroup]->reporting_level != -1){
               	checkme.isItNaughty = checkme.isBlocked;
	} else {
		checkme.isItNaughty = false; 
	        checkme.isBlocked = false;
	}
    }

    if (checkme.isbypass && !(checkme.iscookiebypass || checkme.isvirusbypass)) {
        DEBUG_debug("Setting GBYPASS cookie; bypasstimestamp = ", checkme.bypasstimestamp);
        String ud(checkme.urldomain);
        if (ud.startsWith("www.")) {
            ud = ud.after("www.");
        }

	String outhead = "HTTP/1.1 302 Redirect\r\n";
        outhead += "Set-Cookie: GBYPASS=";
        outhead += icaphead.HTTPrequest.hashedCookie(&ud, ldl->fg[filtergroup]->cookie_magic.c_str(), &clientip,
                                checkme.bypasstimestamp, clientuser).toCharArray();
      //  outhead += hashedCookie(&ud, ldl->fg[filtergroup]->cookie_magic.c_str(), &clientip,
       //                         checkme.bypasstimestamp).toCharArray();
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

// TODO add logic for 204 response etc.
    if (checkme.isexception || checkme.logcategory) {
        std::string code;
        if (checkme.isvirusbypass)
            code = "V";
        else if (checkme.isbypass)
            code = "Y";
        else if (checkme.logcategory)
            code = "L";
        else
            code = "E";

        icaphead.set_icap_com(clientuser,code, filtergroup, checkme.message_no, checkme.log_message_no,
        checkme.whatIsNaughtyLog);
        if (icaphead.allow_204) {
            icaphead.respond(peerconn, "204 No Content", false, false);
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
    if (!done && !checkme.isdone && checkme.isGrey && checkme.isSearch)
        check_search_terms(checkme);  // will set isItNaughty if needed


    // check for CONNECT redirect
    if ((icaphead.HTTPrequest.requestType() == "CONNECT") && checkme.urlmodified) {
        // DEBUG_debug("is CONNECT logurl:", checkme.logurl, " conn site:", checkme.connect_site, " fullurl:", checkme.baseurl, " urldomain:", checkme.urldomain);
        if (checkme.connect_site != checkme.urldomain) {
            icaphead.HTTPrequest.setConnect(checkme.connect_site);
            // DEBUG_debug("after setURL logurl:", checkme.logurl, " conn site:", checkme.connect_site, " fullurl:", checkme.baseurl, " urldomain:", checkme.urldomain);
        }
    }
    // TODO V5 call POST scanning code New NaughtyFilter function????

    if (!done && checkme.isItNaughty) {
        if (genDenyAccess(peerconn, res_hdr, res_body, &icaphead.HTTPrequest, &icaphead.HTTPresponse,
                          &checkme.logurl, &checkme, &clientuser, &clientip,
                          filtergroup, checkme.ispostblock, checkme.headersent, checkme.wasinfected,
                          checkme.scanerror)) {
            icaphead.errorResponse(peerconn, res_hdr, res_body);
            if (icaphead.req_body_flag) {
                peerconn.drainChunk(peerconn.getTimeout());   // drains any body
            }
            done = true;
            DEBUG_debug("ICAP Naughty");
            // break loop "// maintain a persistent connection"
            // return 1;
        };
    }


    if (!done) {
        icaphead.set_icap_com(clientuser, "G", filtergroup, checkme.message_no, checkme.log_message_no,
                              checkme.whatIsNaughtyLog);
        icaphead.respond(peerconn, "200 OK", true);
        if (icaphead.req_body_flag) {
            peerconn.loopChunk(peerconn.getTimeout());   // echoes any body
        }
    }
    //Log
    if (checkme.logcategory || !(checkme.isourwebserver || checkme.nolog)) { // don't log requests to the web server
        doLog(clientuser, clientip, checkme);
    }
    return 0;
}

int ConnectionHandler::handleICAPresmod(Socket &peerconn, String &ip, NaughtyFilter &checkme, ICAPHeader &icaphead,
                                        DataBuffer &docbody) {

    //bool authed = false;
    bool persistPeer = true;
    bool done = false;
    String clientip = ip;
    String res_hdr, res_body;
    std::deque<CSPlugin *> responsescanners;

    // do all of this normalisation etc just the once at the start.
    checkme.setURL();

    overide_persist = false;
    if (icaphead.icap_com.filtergroup < 0)    //i.e. no X-ICAP-E2G
    {
        String wline = "ICAP/1.0 418 Bad composition - X-ICAP-E2G header not present\r\n";
        wline += "Service: ";
	    wline += PACKAGE_STRING; 
	    wline  += "\r\n";
        wline += "Encapsulated: null-body=0\r\n";
        wline += "\r\n";
        peerconn.writeString(wline.toCharArray());
        DEBUG_icap(" ICAP Error: ", wline);
        return 1;
    }

    filtergroup = icaphead.icap_com.filtergroup;
    checkme.filtergroup = icaphead.icap_com.filtergroup;
    clientuser = icaphead.icap_com.user;
    docbody.set_current_config(ldl->fg[filtergroup]);

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
    } else if (icaphead.icap_com.EBG == "L") {   // only log - do not block
        checkme.isexception = true;
        checkme.logcategory = true;
        checkme.message_no = icaphead.icap_com.mess_no;
        checkme.log_message_no = icaphead.icap_com.log_mess_no;
        checkme.whatIsNaughtyLog = icaphead.icap_com.mess_string;
    }

    //int unrealfiltergroup = filtergroup + 1;
    DEBUG_icap("ICAP Respmod enabled - username: ", clientuser,
                        " -filtergroup: ", filtergroup,
                        " icaphead.icap_com.EBG: ", icaphead.icap_com.EBG,
                        " icaphead.res_body_flag: ", icaphead.res_body_flag);

    checkme.clientip = ip;
    checkme.filtergroup = filtergroup;
    //if(o.log_requests) {
    if (e2logger.isEnabled(LoggerSource::requestlog)) {
        std::string fnt = "RESPMOD";
        doRQLog(clientuser, clientip, checkme, fnt);
    }
    // Look up reverse DNS name of client if needed
    if (o.conn.reverse_client_ip_lookups) {
        getClientFromIP(clientip.c_str(), checkme.clienthost);
    }

    //bool part_banned;

    // virus checkichurchillng candidate?
    // checkme.noviruscheck defaults to true
    DEBUG_icap("Virus scan checkme.isexception: ", checkme.isexception,
                        " checkme.noviruscheck: ", checkme.noviruscheck,
                        " content_scan_exceptions: ", ldl->fg[filtergroup]->content_scan_exceptions,
                        " checkme.isBlocked: ", checkme.isBlocked,
                        " disable_content_scan: ", ldl->fg[filtergroup]->disable_content_scan,
                        " csplugins: ", o.plugins.csplugins.size() );

    if (icaphead.res_body_flag    //  can only  scan if  body present
        && !(checkme.isBlocked)  // or not already blocked
        && (o.plugins.csplugins.size() > 0)            //  and we have scan plugins
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
            DEBUG_icap("After StoryB icapcheckresmod", checkme.isexception,
                                " mess_no ", checkme.message_no,
                                " checkme.noviruscheck: ", checkme.noviruscheck,
                                " content_scan_exceptions: ", ldl->fg[filtergroup]->content_scan_exceptions);

	   if (ldl->fg[filtergroup]->reporting_level != -1){
            checkme.isItNaughty = checkme.isBlocked;
	   } else {
		    checkme.isItNaughty = false; 
	        checkme.isBlocked = false;
	   }
    }

    if (checkme.isexception && !checkme.noviruscheck && !ldl->fg[filtergroup]->content_scan_exceptions)
        checkme.noviruscheck = true;

    if (ldl->fg[filtergroup]->content_scan_exceptions && checkme.isexception)
        checkme.noviruscheck = false;

    if ((checkme.isexception && checkme.noviruscheck)|| !icaphead.res_body_flag) {
        if (icaphead.allow_204) {
            icaphead.respond(peerconn, "204 No Content", false, false);
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
                    for (std::deque<Plugin *>::iterator i = o.plugins.csplugins_begin; i != o.plugins.csplugins_end; ++i) {
                        int csrc = ((CSPlugin *)(*i))->willScanRequest(checkme.url, clientuser.c_str(), ldl->fg[filtergroup], clientip.c_str(), false, false, checkme.isexception, checkme.isbypass);
                        if (csrc > 0)
                            responsescanners.push_back((CSPlugin *)(*i));
                        else if (csrc < 0)
                            E2LOGGER_error("willScanRequest returned error: ", csrc);
                    }
                }
                check_content(checkme, docbody,peerconn, peerconn,responsescanners);
    }

    //send response header to client
    if (!done && !checkme.isItNaughty) {
        icaphead.respond(peerconn, "200 OK", true);
        if(checkme.waschecked) {
            if (!docbody.out(&peerconn))
                checkme.pausedtoobig = false;
            if (checkme.pausedtoobig)
                checkme.tunnel_rest = true;
        }
        if (checkme.tunnel_rest){
            peerconn.loopChunk(peerconn.getTimeout());   // echos any body
            done = true;
	}
    }

    if(checkme.isItNaughty) {
        if(genDenyAccess(peerconn,res_hdr, res_body, &icaphead.HTTPrequest, &icaphead.HTTPresponse, &checkme.logurl, &checkme, &clientuser, &ip,
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
int ConnectionHandler::determineGroup(std::string &user, int &fg, StoryBoard &story, NaughtyFilter &cm, int story_entry) {
    if (user.length() < 1 || user == "-") {
        return E2AUTH_NOMATCH;
    }
    cm.user = user;
    if (!story.runFunctEntry(story_entry, cm)) {
        DEBUG_debug("User not in filter groups list for: icap ");
        return E2AUTH_NOGROUP;
    }

    DEBUG_debug("Group found for: ", user.c_str(), " in icap ");
    fg = cm.filtergroup;
    return E2AUTH_OK;
}

