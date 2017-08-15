//ll support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "ICAPHeader.hpp"
#include "Socket.hpp"
#include "OptionContainer.hpp"
#include "FDTunnel.hpp"

#include <unistd.h>
#include <sys/socket.h>
#include <exception>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <cerrno>
#include <zlib.h>

// GLOBALS
extern OptionContainer o;

// IMPLEMENTATION

// set timeout for socket operations
void ICAPHeader::setTimeout(int t)
{
    timeout = t;
}

// reset header object for future use
void ICAPHeader::reset()
{
    if (dirty) {
        header.clear();
        waspersistent = false;
        ispersistent = false;


        phost = NULL;
        pport = NULL;
        pcontentlength = NULL;
        pcontenttype = NULL;
        pproxyauthorization = NULL;
        pauthorization = NULL;
        pproxyauthenticate = NULL;
        pcontentdisposition = NULL;
        puseragent = NULL;
        pxforwardedfor = NULL;
        pcontentencoding = NULL;
        pproxyconnection = NULL;
        pkeepalive = NULL;

        dirty = false;

    }
}

// *
// *
// * header value and type checks
// *
// *

// grab request type (GET, HEAD etc.)
String ICAPHeader::requestType()
{
    return header.front().before(" ");
}

// grab return code
int ICAPHeader::returnCode()
{
    if (header.size() > 0) {
        return header.front().after(" ").before(" ").toInteger();
    }else {
        return 0;
    }
}

// grab content length


// *
// *
// * header modifications
// *
// *



// modifies the URL in all relevant header lines after a regexp search and replace
// setURL Code originally from from Ton Gorter 2004
void ICAPHeader::setURL(String &url)
{
    String hostname;
    bool https = (url.before("://") == "https");
    int port = (https ? 443 : 80);

    if (!url.after("://").contains("/")) {
        url += "/";
    }
    hostname = url.after("://").before("/");
    if (hostname.contains("@")) { // Contains a username:password combo
        hostname = hostname.after("@");
    }
    if (hostname.contains(":")) {
        port = hostname.after(":").toInteger();
        if (port == 0 || port > 65535) {
            port = (https ? 443 : 80);
        }
        hostname = hostname.before(":"); // chop off the port bit
    }

#ifdef DGDEBUG
    std::cout << "setURL: header.front() changed from: " << header.front() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    if (!https)
        header.front() = header.front().before(" ") + " " + url + " " + header.front().after(" ").after(" ");
    else
        // Should take form of "CONNECT example.com:443 ICAP/1.0" for SSL
        header.front() = header.front().before(" ") + " " + hostname + ":" + String(port) + " " + header.front().after(" ").after(" ");
#ifdef DGDEBUG
    std::cout << " to: " << header.front() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    if (phost != NULL) {
#ifdef DGDEBUG
        std::cout << "setURL: header[] line changed from: " << (*phost) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        (*phost) = String("Host: ") + hostname;
        if (port != (https ? 443 : 80)) {
            (*phost) += ":";
            (*phost) += String(port);
        }
        (*phost) += "\r";
#ifdef DGDEBUG
        std::cout << " to " << (*phost) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    }
    if (pport != NULL) {
#ifdef DGDEBUG
        std::cout << "setURL: header[] line changed from: " << (*pport) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        (*pport) = String("Port: ") + String(port) + "\r";
#ifdef DGDEBUG
        std::cout << " to " << (*pport) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    }
}


// *
// *
// * detailed header checks & fixes
// *
// *





// fix bugs in certain web servers that don't obey standards.
// actually, it's us that don't obey standards - HTTP RFC says header names
// are case-insensitive. - Anonymous SF Poster, 2006-02-23
void ICAPHeader::checkheader(bool allowpersistent)
{
    // are these headers outgoing (from browser), or incoming (from web server)?
    // Hum Maybe there is something wrong but it should be always from client
    bool outgoing = true;
    if (header.front().startsWith("HT")) {
        outgoing = false;
    }

    if (header.size() > 1) {
    for (std::deque<String>::iterator i = header.begin() + 1; i != header.end(); i++) { // check each line in the headers
        // index headers - try to perform the checks in the order the average browser sends the headers.
        // also only do the necessary checks for the header type (sent/received).
        // Sequencial if else
	if (outgoing && (phost == NULL) && i->startsWithLower("host:")) {
            phost = &(*i);
            // don't allow through multiple host headers
        } else if (outgoing && (phost != NULL) && i->startsWithLower("host:")) {
            i->assign("X-E2G-IgnoreMe: removed multiple host headers\r");
        } else if ((!outgoing) && (pcontentencoding == NULL) && i->startsWithLower("content-encoding:")) {
            pcontentencoding = &(*i);
        } else if ((!outgoing) && (pkeepalive == NULL) && i->startsWithLower("keep-alive:")) {
            pkeepalive = &(*i);
        } else if ((pcontenttype == NULL) && i->startsWithLower("content-type:")) {
            pcontenttype = &(*i);
        } else if ((pcontentlength == NULL) && i->startsWithLower("content-length:")) {
            pcontentlength = &(*i);
        }
        // is this ever sent outgoing?
        else if ((pcontentdisposition == NULL) && i->startsWithLower("content-disposition:")) {
            pcontentdisposition = &(*i);
        } else if ((pproxyauthorization == NULL) && i->startsWithLower("proxy-authorization:")) {
            pproxyauthorization = &(*i);
        } else if ((pauthorization == NULL) && i->startsWithLower("authorization:")) {
            pauthorization = &(*i);
        } else if ((pproxyauthenticate == NULL) && i->startsWithLower("proxy-authenticate:")) {
            pproxyauthenticate = &(*i);
        } else if ((pproxyconnection == NULL) && (i->startsWithLower("proxy-connection:") || i->startsWithLower("connection:"))) {
            pproxyconnection = &(*i);
        } else if (outgoing && (pxforwardedfor == NULL) && i->startsWithLower("x-forwarded-for:")) {
            pxforwardedfor = &(*i);
        }
        // this one's non-standard, so check for it last
        else if (outgoing && (pport == NULL) && i->startsWithLower("port:")) {
            pport = &(*i);
        }

	//Can be placed anywhere ..
        if (outgoing && i->startsWithLower("upgrade-insecure-requests:")) {
            i->assign("X-E2G-IgnoreMe: removed upgrade-insecure-requests\r");
        }


#ifdef DGDEBUG
        std::cout << "Header value from client: " << (*i) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    }
}

    //if its http1.1
    bool onepointone = false;
    if (header.front().after("ICAP/").startsWith("1.1")) {
#ifdef DGDEBUG
        std::cout << "CheckHeader: ICAP/1.1 detected" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        onepointone = true;
        // force ICAP/1.0 - we don't support chunked transfer encoding, possibly amongst other things
        if (outgoing)
            header.front() = header.front().before(" ICAP/") + " ICAP/1.0\r";
    }

    //work out if we should explicitly close this connection after this request
    bool connectionclose;
    if (pproxyconnection != NULL) {
        if (pproxyconnection->contains("lose")) {
#ifdef DGDEBUG
            std::cout << "CheckHeader: P-C says close" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            connectionclose = true;
        } else {
            connectionclose = false;
        }
    } else {
        connectionclose = true;
    }

    // Do not allow persistent connections on CONNECT requests - the browser thinks it has a tunnel
    // directly to the external server, not a connection to the proxy, so it won't be re-used in the
    // manner expected by DG and will result in waiting for time-outs.  Bug identified by Jason Deasi.
    bool isconnect = false;
    if (outgoing && header.front()[0] == 'C') {
#ifdef DGDEBUG
        std::cout << "CheckHeader: CONNECT request detected" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        isconnect = true;
    }

#ifdef DGDEBUG
    std::cout << "CheckHeader flags before normalisation: AP=" << allowpersistent << " PPC=" << (pproxyconnection != NULL)
              << " 1.1=" << onepointone << " connectionclose=" << connectionclose << " CL=" << (pcontentlength != NULL) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    if (connectionclose || (outgoing ? isconnect : (pcontentlength == NULL))) {
        // couldnt have done persistency even if we wanted to
        allowpersistent = false;
    }

    if (outgoing) {
        // Even though persistent CONNECT requests usually break things, waspersistent should
        // reflect the intention of the original request headers, or NTLM breaks.
        if (isconnect && !connectionclose) {
            waspersistent = true;
        }
    } else {
        if (!connectionclose && !(pcontentlength == NULL)) {
            waspersistent = true;
        }
    }

#ifdef DGDEBUG
    std::cout << "CheckHeader flags after normalisation: AP=" << allowpersistent << " WP=" << waspersistent << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    // force the headers to reflect whether or not persistency is allowed
    // (modify pproxyconnection or add connection close/keep-alive - Client version, of course)
    if (allowpersistent) {
        if (pproxyconnection == NULL) {
#ifdef DGDEBUG
            std::cout << "CheckHeader: Adding our own Proxy-Connection: Keep-Alive" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            header.push_back("Connection: keep-alive\r");
            pproxyconnection = &(header.back());
        } else {
            (*pproxyconnection) = "Connection: keep-alive\r";
        }
    } else {
        if (pproxyconnection == NULL) {
#ifdef DGDEBUG
            std::cout << "CheckHeader: Adding our own Proxy-Connection: Close" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            header.push_back("Connection: close\r");
            pproxyconnection = &(header.back());
        } else {
            (*pproxyconnection) = "Connection: close\r";
        }
    }

    ispersistent = allowpersistent;

    // Normalise request headers (fix host, port, first line of header, etc. to all be consistent)
    if (outgoing) {
        String newurl(getUrl());
        setURL(newurl);
    }
}

String ICAPHeader::getUrl()
{
    // Version of URL *with* port is not cached,
    // as vast majority of our code doesn't like
    // port numbers in URLs.
    port = 80;
    bool https = false;
    String hostname;
    String userpassword;
    String answer(header.front().after(" "));
    answer.removeMultiChar(' ');
    if (answer.after(" ").startsWith("ICAP/")) {
        answer = answer.before(" ICAP/");
    } else {
        answer = answer.before(" http/"); // just in case!
    }
    if (requestType() == "CONNECT") {
        https = true;
        port = 443;
        if (!answer.startsWith("https://")) {
            answer = "https://" + answer;
        }
    }
    if (pport != NULL) {
        port = pport->after(" ").toInteger();
        if (port == 0 || port > 65535)
            port = (https ? 443 : 80);
    }
    if (answer.length()) {
        if (answer[0] == '/') { // must be the latter above
            if (phost != NULL) {
                hostname = phost->after(" ");
                hostname.removeWhiteSpace();
                if (hostname.contains(":")) {
                    port = hostname.after(":").toInteger();
                    if (port == 0 || port > 65535) {
                        port = (https ? 443 : 80);
                    }
                    hostname = hostname.before(":");
                }
                while (hostname.endsWith("."))
                    hostname.chop();
                hostname = "http://" + hostname;
                answer = hostname + answer;
            }
            // Squid doesn't like requests in this format. Work around the fact.
            header.front() = requestType() + " " + answer + " ICAP/" + header.front().after(" ICAP/");
        } else { // must be in the form GET http://foo.bar:80/ HTML/1.0
            if (!answer.after("://").contains("/")) {
                answer += "/"; // needed later on so correct host is extracted
            }
            String protocol(answer.before("://"));
            hostname = answer.after("://");
            String url(hostname.after("/"));
            url.removeWhiteSpace(); // remove rubbish like ^M and blanks
            if (hostname.endsWith(".")) {
                hostname.chop();
            }
            if (url.length() > 0) {
                url = "/" + url;
            }
            hostname = hostname.before("/"); // extra / was added 4 here
            if (hostname.contains("@")) { // Contains a username:password combo
                userpassword = hostname.before("@");
                hostname = hostname.after("@");
            }
            if (hostname.contains(":")) {
                port = hostname.after(":").toInteger();
                if (port == 0 || port > 65535) {
                    port = (https ? 443 : 80);
                }
                hostname = hostname.before(":"); // chop off the port bit
            }
            while (hostname.endsWith("."))
                hostname.chop();
            if (userpassword.length())
                answer = protocol + "://" + userpassword + "@" + hostname + url;
            else
                answer = protocol + "://" + hostname + url;
        }
    }

#ifdef DGDEBUG
    std::cout << "from header url:" << answer << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    return answer;
}

String ICAPHeader::url()
{
    return getUrl();
}

// *
// *
// * URL and Base64 decoding funcs
// *
// *


// turn %xx back into original character
String ICAPHeader::hexToChar(const String &n, bool all)
{
    if (n.length() < 2) {
        return String(n);
    }
    static char buf[2];
    unsigned int a, b;
    unsigned char c;
    a = n[0];
    b = n[1];
    if (a >= 'a' && a <= 'f') {
        a -= 87;
    } else if (a >= 'A' && a <= 'F') {
        a -= 55;
    } else if (a >= '0' && a <= '9') {
        a -= 48;
    } else {
        return String("%") + n;
    }
    if (b >= 'a' && b <= 'f') {
        b -= 87;
    } else if (b >= 'A' && b <= 'F') {
        b -= 55;
    } else if (b >= '0' && b <= '9') {
        b -= 48;
    } else {
        return String("%") + n;
    }
    c = a * 16 + b;
    if (all || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-')) {
        buf[0] = c;
        buf[1] = '\0';
        return String(buf);
    } else {
        return String("%") + n;
    }
}

// decode a line of base64
std::string ICAPHeader::decodeb64(const String &line)
{ // decode a block of b64 MIME
    long four = 0;
    int d;
    std::string result;
    int len = line.length() - 4;
    for (int i = 0; i < len; i += 4) {
        four = 0;
        d = decode1b64(line[i + 0]);
        four = four | d;
        d = decode1b64(line[i + 1]);
        four = (four << 6) | d;
        d = decode1b64(line[i + 2]);
        four = (four << 6) | d;
        d = decode1b64(line[i + 3]);
        four = (four << 6) | d;
        d = (four & 0xFF0000) >> 16;
        result += (char)d;
        d = (four & 0xFF00) >> 8;
        result += (char)d;
        d = four & 0xFF;
        result += (char)d;
    }
    return result;
}

// decode an individual base64 character
int ICAPHeader::decode1b64(char c)
{
    unsigned char i = '\0';
    switch (c) {
    case '+':
        i = 62;
        break;
    case '/':
        i = 63;
        break;
    case '=':
        i = 0;
        break;
    default: // must be A-Z, a-z or 0-9
        i = '9' - c;
        if (i > 0x3F) { // under 9
            i = 'Z' - c;
            if (i > 0x3F) { // over Z
                i = 'z' - c;
                if (i > 0x3F) { // over z so invalid
                    i = 0x80; // so set the high bit
                } else {
                    // a-z
                    i = c - 71;
                }
            } else {
                // A-Z
                i = c - 65;
            }
        } else {
            // 0-9
            i = c + 4;
        }
        break;
    }
    return (int)i;
}

// *
// *
// * network send/receive funcs
// *
// *

// send headers out over the given socket
// "reconnect" flag gives permission to reconnect to the socket on write error
// - this allows us to re-open the proxy connection on pconns if squid's end has
// timed out but the client's end hasn't. not much use with NTLM, since squid
// will throw a 407 and restart negotiation, but works well with basic & others.
//void ICAPHeader::out(Socket *peersock, Socket *sock, int sendflag, bool reconnect) throw(std::exception)
bool ICAPHeader::out(Socket *peersock, Socket *sock, int sendflag, bool reconnect )
{
    String l; // for amalgamating to avoid conflict with the Nagel algorithm

    if (sendflag == __DGHEADER_SENDALL || sendflag == __DGHEADER_SENDFIRSTLINE) {
        if (header.size() > 0) {
            l = header.front() + "\n";

#ifdef DGDEBUG
            if(is_response)  {
    std::cout << "response headerout:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
    } else {
    std::cout << "request headerout:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
    }
#endif

#ifdef __SSLMITM
            //if a socket is ssl we want to send relative paths not absolute urls
            //also ICAP responses dont want to be processed (if we are writing to an ssl client socket then we are doing a request)
            if (sock->isSsl() && !sock->isSslServer()) {
                //GET http://support.digitalbrain.com/themes/client_default/linerepeat.gif ICAP/1.0
                //	get the request method		//get the relative path					//everything after that in the header
                l = header.front().before(" ") + " /" + header.front().after("://").after("/").before(" ") + " ICAP/1.0\r\n";
            }
#endif

#ifdef DGDEBUG
            if(is_response)  {
    std::cout << "response headerout:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
    } else {
    std::cout << "request headerout:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
    }
#endif
            // first reconnect loop - send first line
            while (true) {
                if (!sock->writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
                    // throw std::exception();
                    return false;
                }
                // if we got here, we succeeded, so break the reconnect loop
#ifdef DGDEBUG
                std::cout << "headertoclient:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
                std::cout << "timeout:" << timeout << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                break;
            }
        }
        if (sendflag == __DGHEADER_SENDFIRSTLINE) {
            return true;
        }
    }

    l = "";

    if (header.size() > 1) {
        for (std::deque<String>::iterator i = header.begin() + 1; i != header.end(); i++) {
            if (! (*i).startsWith("X-E2G-IgnoreMe")){
#ifdef DGDEBUG
                std::cout << "Found Header: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                l += (*i) + "\n";
            }
#ifdef DGDEBUG
            else {
                    std::cout << "Found Header X-E2G-IgnoreMe: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
            }
#endif
        }

    }
    l += "\r\n";

    // second reconnect loop
    while (true) {
        // send header to the output stream
        // need exception for bad write

        if (!sock->writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
            //throw std::exception();
            return false;
        }
        // if we got here, we succeeded, so break the reconnect loop
        break;
    }

#ifdef DGDEBUG
    std::cout << "Returning from header:out " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    return true;
}

void ICAPHeader::setClientIP(String &ip) {
    s_clientip = ip.toCharArray();
}

bool ICAPHeader::in(Socket *sock, bool allowpersistent)
{
    if (dirty)
        reset();
    dirty = true;

#ifdef DGDEBUG
    if(is_response)
    std::cout << "Start of response header:in"  << std::endl;
    else
    std::cout << "Start of request header:in"  << std::endl;
#endif

    // the RFCs don't specify a max header line length so this should be
    // dynamic really.  Pointed out (well reminded actually) by Daniel Robbins
    char buff[32768]; // setup a buffer to hold the incomming ICAP line
    String line; // temp store to hold the line after processing
    line = "----"; // so we get past the first while
    bool firsttime = true;
    bool discard = false;
    while (line.length() > 3 || discard) { // loop until the stream is
    // failed or we get to the end of the header (a line by itself)

    // get a line of header from the stream
    // on the first time round the loop, honour the reloadconfig flag if desired
    // - this lets us break when waiting for the next request on a pconn, but not
    // during receipt of a request in progress.
        bool truncated = false;
        int rc;
        bool honour_reloadconfig = false;  // TEMPORARY FIX!!!!
        if (firsttime) {
#ifdef DGDEBUG
            std::cout << "header:in before getLine - timeout:" << timeout << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            rc = sock->getLine(buff, 32768, timeout, firsttime ? honour_reloadconfig : false, NULL, &truncated);
#ifdef DGDEBUG
            std::cout << "firstime: header:in after getLine " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
           if (rc < 0 || truncated) {
                ispersistent = false;
#ifdef DGDEBUG
                std::cout << "firstime: header:in after getLine: rc: " << rc << " truncated: " << truncated  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                return false;
            }
        } else {
        //rc = sock->getLine(buff, 32768, 100, firsttime ? honour_reloadconfig : false, NULL, &truncated);   // timeout reduced to 100ms for lines after first
        // this does not work for sites who are slow to send Content-Lenght so revert to standard
        // timeout
            rc = sock->getLine(buff, 32768, timeout, firsttime ? honour_reloadconfig : false, NULL, &truncated);   // timeout reduced to 100ms for lines after first
            if (rc < 0 || truncated) {
                ispersistent = false;
#ifdef DGDEBUG
                std::cout << "not firstime header:in after getLine: rc: " << rc << " truncated: " << truncated << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                return false;        // do not allow non-terminated headers
            }

        }

        if (header.size() > o.max_header_lines) {
#ifdef DGDEBUG
            std::cout << "header:size too big =  " << header.size() << " Lines: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            ispersistent = false;
            return false;
        }

     //       throw std::exception();

        // getline will throw an exception if there is an error which will
        // only be caught by HandleConnection()       ?????????????????????

        if (rc > 0 ) line = buff;
        else line = "";// convert the line to a String

        if(firsttime && is_response) {
        // check first line header
            if (!(line.length() > 11 && line.startsWith("ICAP/") && (line.after(" ").before(" ").toInteger() > 99)))
            {
                if(o.logconerror)
                    syslog(LOG_INFO, "Server did not respond with ICAP");
#ifdef DGDEBUG
                std::cout << "Returning from header:in Server did not respond with ICAP " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                return false;
            }
        }
        // ignore crap left in buffer from old pconns (in particular, the IE "extra CRLF after POST" bug)
        discard = false;
        if (not(firsttime && line.length() <= 3)) {
            header.push_back(line); // stick the line in the deque that holds the header
        } else {
            discard = true;
#ifdef DGDEBUG
            std::cout << "Discarding unwanted bytes at head of request (pconn closed or IE multipart POST bug)" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        }
        firsttime = false;
#ifdef DGDEBUG
        std::cout << "Loop catch Header IN from client: " << line << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
// End of while
    }

    if (header.size() == 0) {
#ifdef DGDEBUG
        std::cout << "header:size = 0 " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return false;
    }

    header.pop_back(); // remove the final blank line of a header
    checkheader(allowpersistent); // sort out a few bits in the header
    return true;
}
