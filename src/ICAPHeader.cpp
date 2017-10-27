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
//#include "DebugManager.hpp"
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

//DebugManager * myDebug = new DebugManager(o.debuglevel);

// set timeout for socket operations

ICAPHeader::ICAPHeader() : port(0), timeout(120000),  dirty(true), myDebug(new DebugManager(o.debuglevel))
{
    reset();
}

ICAPHeader::ICAPHeader(int type) : port(0), timeout(120000),  dirty(true), is_response(false)
{
    reset();
    setType(type);
}

void ICAPHeader::setTimeout(int t)
{
    timeout = t;
}

void ICAPHeader::setHTTPhdrs(HTTPHeader &req, HTTPHeader &res) {
    HTTPrequest = &req;
    HTTPresponse = &res;
}

bool ICAPHeader::setEncapRecs() {
    String t = *pencapsulated;
    std::cerr << "pencapsulated is " << t << std::endl;
    t = t.after(": ");
    std::cerr << "stripped pencapsulated is " << t << std::endl;
    while ( t.length() ) {
        String t1 = t.before(",");
        if (t1 == "")
            t1 = t;
        struct encap_rec erec;
        erec.name = t1.before("=");
        String t2 = t1.after("=");
        if (erec.name ==  "" || t2 == "")
            return false;
        erec.value = t2.toInteger();
        encap_recs.push_back(erec);
        t = t.after(",");
    }
}

// reset header object for future use
void ICAPHeader::reset()
{
    if (dirty) {
        header.clear();
        encap_recs.clear();
        waspersistent = false;
        ispersistent = false;


        pproxyconnection = NULL;
        pencapsulated= NULL;
        pauthorization = NULL;
        pallow= NULL;
        allow_204 = false;
        pfrom= NULL;
        phost = NULL;
        preferer = NULL;
        puseragent = NULL;
        pxforwardedfor = NULL;
        pkeepalive = NULL;
        pupgrade = NULL;
        pencapsulated = NULL;

        pproxyauthorization = NULL;
        pproxyauthenticate = NULL;
        pcontentdisposition = NULL;
        pclientip= NULL;
        pclientuser= NULL;

        req_hdr_flag = false;
        res_hdr_flag = false;
        out_req_hdr_flag = false;
        out_res_hdr_flag = false;
        req_body_flag = false;
        res_body_flag = false;
        opt_body_flag = false;
        null_body_flag = false;
        service_reqmod = false;
        service_resmod = false;
        service_options = false;
        icap_reqmod_service = false;
        icap_resmod_service = false;

        dirty = false;

    }
}

// *
// *
// * header value and type checks
// *
// *

// grab request type (REQMOD, RESPMOD, OPTIONS)
String ICAPHeader::requestType()
{
    return header.front().before(" ");
}

// grab return code
int ICAPHeader::returnCode()    // does not apply to ICAP ?  May do if we use for ICAP client
{
    if (header.size() > 0) {
        return header.front().after(" ").before(" ").toInteger();
    }else {
        return 0;
    }
}


// *
// *
// * header modifications
// *
// *

#ifdef NOTDEF
// modifies the URL in all relevant header lines after a regexp search and replace
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
    	
    if(o.debuglevel != "")
    {
	std::ostringstream oss (std::ostringstream::out);
	oss << "setURL: header.front() changed from: " << header.front() << " Line: " << __LINE__ << " Function: " << __func__ ;
	myDebug->Debug("HEADER,ICAP", oss.str());
    }


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

#endif


// *
// *
// * detailed header checks & fixes
// *
// *

void ICAPHeader::checkheader(bool allowpersistent)
{
    bool outgoing = true;

    if (header.size() > 1) {
    for (std::deque<String>::iterator i = header.begin() + 1; i != header.end(); i++) { // check each line in the headers
        // index headers - try to perform the checks in the order the average browser sends the headers.
        // also only do the necessary checks for the header type (sent/received).
        // Sequencial if else

	if(o.debuglevel != "")
	{
		std::ostringstream oss (std::ostringstream::out);
		oss << "Checking header: " << &(*i) << " Line: " << __LINE__ << " Function: " << __func__;
		myDebug->Debug("HEADER", oss.str());
	}

        if ((phost == NULL) && i->startsWithLower("host:")) {
            phost = &(*i);
        } else if ((pauthorization == NULL) && i->startsWithLower("authorization:")) {
            pauthorization = &(*i);
        } else if ((pallow == NULL) && i->startsWithLower("allow:")) {
            pallow = &(*i);
            allow_204 = pallow->contains("204");
        } else if ((pfrom == NULL) && i->startsWithLower("from:")) {
            pfrom = &(*i);
        } else if ((phost == NULL) && i->startsWithLower("host:")) {
            phost = &(*i);
        } else if ((ppreview == NULL) && i->startsWithLower("preview:")) {
            ppreview = &(*i);
            allow_204 = true;
        } else if ((pkeepalive == NULL) && i->startsWithLower("keep-alive:")) {
            pkeepalive = &(*i);
        } else if (i->startsWithLower("encapsulated:")) {
            pencapsulated = &(*i);
            setEncapRecs();
            //i->assign("X-E2G-IgnoreMe: encapuslated always regenerated\r");
        } else if (i->startsWithLower("x-client-ip:")) {
            pclientip = &(*i);
            String t = pclientip->after(": ");
            t.chop();
            setClientIP(t);
        } else if (i->startsWithLower("x-client-username:")) {
            pclientuser = &(*i);
            username = pclientuser->after(": ");
            username.chop();
        }
#ifdef DGDEBUG
        std::cout << "Header value from ICAP client: " << (*i) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;

        std::cout << "allow_204 is " << allow_204 << std::endl;
#endif
    }
}

}

#ifdef NOTDEF
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


    if(o.debuglevel != "")
    {
	std::ostringstream oss (std::ostringstream::out);
	oss << "from header url:" << answer << " Line: " << __LINE__ << " Function: " << __func__;
	myDebug->Debug("ICAP", oss.str());
    }

    return answer;
}

String ICAPHeader::url()
{
    return getUrl();
}
#endif

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
bool ICAPHeader::respond(Socket &sock, String res_code, bool echo)
{
    bool body_done = false;

    std::cerr << "ICAPresponse starting - RCode " << res_code << "echo is " << echo << std::endl;

    String l; // for amalgamating to avoid conflict with the Nagel algorithm
    if(echo) {
        if (service_reqmod && !(out_res_hdr_flag || out_req_hdr_flag)) {
            out_req_header = HTTPrequest->stringHeader();
            std::cerr << "out_req_header copied from HTTPrequest :" << out_req_header << std::endl;
            out_req_hdr_flag = true;
            if (req_body > 0)
                size_req_body = req_body; // TODO Check this!
        }

        if (service_resmod && !(out_res_hdr_flag)) {
            out_res_header = HTTPresponse->stringHeader();
            out_res_hdr_flag = true;
            if (res_body > 0)
                size_res_body = res_body;// TODO Check this!
        }
    }


    l = "ICAP/1.0 " + res_code + "\r\n";
    l += "ISTag:";
    l += ISTag;
    l += "\r\n";

    // add Encapsulated header logic
    int offset = 0;
    String soffset (offset);
    String sep = " ";
    l += "Encapsulated:";
    if (out_req_hdr_flag && out_req_header.size() > 0) {
        l += sep;
        sep = ", ";
        l += "req-hdr=";
        l += soffset;
        offset += out_req_header.size();
        soffset = offset;
    }
    if (out_res_hdr_flag && out_res_header.size() > 0) {
        l += sep;
        sep = ", ";
        l += "res-hdr=";
        l += soffset;
        offset += out_res_header.size();
        soffset = offset;
    }
    if (out_req_body_flag) {
    l += sep;
    l += "req-body=";
    l += soffset;
    } else if (out_res_body_flag) {
        l += sep;
        l += "res-body=";
        l += soffset;
    } else {
        l += sep;
        l += "null-body=";
        l += soffset;
    }
    l += "\r\n\r\n";

        // send header to the output stream
        // need exception for bad write
    if (out_req_hdr_flag ) {
        String temp = out_req_header.toCharArray();
        l += temp;
    }

    if (out_res_hdr_flag ) {
        String temp = out_res_header.toCharArray();
        l += temp;
    }

if(o.debuglevel != "")
     {
         std::ostringstream oss (std::ostringstream::out);
         oss  << "Icap response header is: " << l;
         myDebug->Debug("HEADER,ICAP", oss.str());
     }

    if (!sock.writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
        return false;
    }



#ifdef DGDEBUG
    std::cerr << "Returning from icapheader:respond" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    return true;
}

bool  ICAPHeader::errorResponse(Socket &peerconn, String &res_header, String &res_body) {
    // set IAP outs and then output ICAP header and res_header/body
    out_res_header = res_header;
    out_res_hdr_flag = true;
    out_res_body_flag = true;
    if (res_body.length() < 0) {
        out_res_body = res_body;
        out_res_body_flag = true;
    }
    std::cerr << "out_res_header: " << out_res_header << std::endl;
    std::cerr << "out_res_body: " << out_res_body << std::endl;
    if (!respond(peerconn))
        return false;
    if (!peerconn.writeChunk((char*)res_body.toCharArray(), res_body.length(), timeout))
        return false;
    char nothing[3];
    nothing[0] = '\0';
    if (!peerconn.writeChunk(nothing, 0, timeout))
        return false;
    return true;
}

void ICAPHeader::setClientIP(String &ip) {
    clientip = ip;
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
    std::cout << "Start of request ICAPheader:in"  << std::endl;
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
        bool truncated = false;
        int rc;
        bool honour_reloadconfig = false;  // TEMPORARY FIX!!!!
        if (firsttime) {
#ifdef DGDEBUG
            std::cout << "ICAPheader:in before getLine - timeout:" << timeout << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            rc = sock->getLine(buff, 32768, timeout, firsttime ? honour_reloadconfig : false, NULL, &truncated);
#ifdef DGDEBUG
            std::cout << "firstime: ICAPheader:in after getLine " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            if (rc == 0) return false;
            if (rc < 0 || truncated) {
                ispersistent = false;
#ifdef DGDEBUG
                std::cout << "firstime: ICAPheader:in after getLine: rc: " << rc << " truncated: " << truncated  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                return false;
            }
        } else {
            rc = sock->getLine(buff, 32768, timeout, firsttime ? honour_reloadconfig : false, NULL,
                               &truncated);   // timeout reduced to 100ms for lines after first
            if (rc == 0) return false;
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
	    //syslog(LOG_INFO, "header:size too big: %d, see maxheaderlines", header.size());
            ispersistent = false;
            return false;
        }

        //       throw std::exception();

        // getline will throw an exception if there is an error which will
        // only be caught by HandleConnection()       ?????????????????????

        if (rc > 0) line = buff;
        else line = "";// convert the line to a String

        if (firsttime) {
            // check first line header
            if (is_response) {
                if (!(line.length() > 11 && line.startsWith("ICAP/") &&
                      (line.after(" ").before(" ").toInteger() > 99))) {
                    if (o.logconerror)
             //           syslog(LOG_INFO, "Server did not respond with ICAP");
#ifdef DGDEBUG
                    std::cout << "Returning from header:in Server did not respond with ICAP " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                    return false;
                }
            } else {
                method = line.before(" ");
                std::cerr << "line is " << line << std::endl;
                String t = line.after(" ").before(" ");
                std::cerr << "t is " << t << std::endl;
                if (t.startsWith("icap://")) {
                    // valid protocol
                } else {
                    icap_error = "400 Bad Request";
                    return false;
                }
                t = t.after("//").after("/");
                if (t == o.icap_reqmod_url) {
                    icap_reqmod_service = true;
                } else if (t == o.icap_resmod_url) {
                    icap_resmod_service = true;
                } else {
                    icap_error = "404 ICAP Service not found";
                }
                if (method == "OPTIONS") {
                    service_options = true;
                } else if (icap_reqmod_service && method == "REQMOD") {
                    service_reqmod = true;
                } else if (icap_resmod_service && method == "RESMOD") {
                    service_resmod = true;
                } else {
                    icap_error = "405 Method not allowed for service";
                }
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

    //now need to get http req and res headers - if present
    HTTPrequest->reset();
    HTTPresponse->reset();
    if(encap_recs.size() > 0) {
        for (std::deque<encap_rec>::iterator i = encap_recs.begin(); i < encap_recs.end(); i++) {
            if (i->name == "req-hdr") {
                req_hdr_flag = HTTPrequest->in(sock);
                if (!req_hdr_flag)
                    return false;
                req_hdr = i->value;
            } else if (i->name == "res-hdr") {
                res_hdr_flag = HTTPresponse->in(sock);
                if (!res_hdr_flag)
                    return false;
                res_hdr = i->value;
            } else if (i->name == "req-body") {
                req_body_flag = true;
                req_body = i->value;
            } else if (i->name == "res-body") {
                res_body_flag = true;
                res_body = i->value;
            } else if (i->name == "null-body") {
                null_body_flag = true;
                null_body = i->value;
            } else if (i->name == "opt-body") {      // may not need this as only sent in respone
                opt_body_flag = true;
                opt_body = i->value;
            }
            // add further checking in here for REQMOD, RESPMOD and OPTIONS
        }
    }


    return true;
}
