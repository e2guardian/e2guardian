//ll support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "HTTPHeader.hpp"
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
extern thread_local std::string thread_id;

// regexp for decoding %xx in URLs
extern RegExp urldecode_re;

// IMPLEMENTATION

// set timeout for socket operations
void HTTPHeader::setTimeout(int t)
{
    timeout = t;
}

// reset header object for future use
void HTTPHeader::reset()
{
    if (dirty) {
        header.clear();
        waspersistent = false;
        ispersistent = false;

        cachedurl = "";

        addheaderchecked = false;
        isheaderadded = false;
        searchwds = "";
        issearch = false;
        searchchecked = false;
        clcached = false;
        expects_100 = false;

        mitm = false;
        isdirect = false;
        chunked = false;

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
        ptransfercoding = NULL;
        ptransferencoding = NULL;
        pproxyconnection = NULL;
        pkeepalive = NULL;

        useragent = "";
        contenttype = "";
        contentencoding = "";
        transferencoding = "";

        contentlength = -1;
        requesttype = "";
        returncode  = 0;

        dirty = false;

        isProxyRequest = false;
        icap = false;

        delete postdata;
        postdata = NULL;
        postdata_len = 0;
    }
}

// *
// *
// * header value and type checks
// *
// *

// grab request type (GET, HEAD etc.)
String HTTPHeader::requestType()
{
    return requesttype;
}

// grab return code
int HTTPHeader::returnCode()
{
    return returncode;
}

// grab content length
off_t HTTPHeader::contentLength()
{
        return contentlength;
}

// grab the auth type
String HTTPHeader::getAuthType()
{
    if (pproxyauthorization != NULL) {
        return pproxyauthorization->after(" ").before(" ");
    }
    return "";
}

// check the request's return code to see if it's an auth required message
bool HTTPHeader::authRequired()
{
    if (returncode == 407)
        return true;
    else
        return false;
}

// grab content disposition
String HTTPHeader::disposition()
{
    if (pcontentdisposition != NULL) {
        String filename(pcontentdisposition->after("filename").after("="));
        if (filename.contains(";"))
            filename = filename.before(";");
        filename.removeWhiteSpace(); // incase of trailing space
        if (filename.contains("\"")) {
            return filename.after("\"").before("\"");
        }
        return filename;
        // example format:
        // Content-Disposition: attachment; filename="filename.ext"
        // Content-Disposition: attachment; filename=filename.ext
        // Content-Disposition: filename="filename.ext"
        // 3rd format encountered from download script on realVNC's
        // website. notice it does not contain any semicolons! PRA 4-11-2005
    }
    return ""; // it finds the header proposed filename
}

// grab the user agent
String HTTPHeader::userAgent()
{
    return useragent;
}

// grab the content type header
String HTTPHeader::getContentType()
{
    if (pcontenttype != NULL) {
        String mimetype(pcontenttype->after(" "));
        if (mimetype.length() < 1)
            return "-";

        mimetype.chop();

        if (mimetype.contains(" "))
            mimetype = mimetype.before(" ");

        if (mimetype.contains(";"))
            mimetype = mimetype.before(";");

        mimetype.toLower();
        return mimetype;
    }
    return "-";
}

// grab the boundary for multi-part MIME POST data
String HTTPHeader::getMIMEBoundary()
{
    if (pcontenttype != NULL) {
        String boundary(pcontenttype->after(" "));
        boundary.chop();

        if (!boundary.contains("boundary="))
            return "";

        boundary = boundary.after("boundary=");
        if (boundary.contains(";"))
            boundary = boundary.after(";");

        if (boundary[0] == '"') {
            boundary.lop();
            boundary.chop();
        }

        return boundary;
    }
    return "";
}

// does the given content type string match our headers?
bool HTTPHeader::isContentType(const String &t, FOptionContainer* &foc)
{
#ifdef E2DEBUG
             std::cerr << thread_id << "mime type: " << getContentType() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
// Do standard check first!
   if (getContentType().startsWith(t))
	return true;

// Only check text_mime types if ContentType request is 'text'
   if (t == "text") {
        String mime = getContentType();
        std::deque<std::string> text_mime =  foc->text_mime;
        int size = (int) text_mime.size();
        int i;
        for (i = 0; i < size; i++) {
            if (mime.startsWith(text_mime[i])) {
#ifdef E2DEBUG
                std::cerr << thread_id << "mimes match : " << text_mime[i] << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                return true;
           }
#ifdef E2DEBUG
	   else {
                std::cerr << thread_id << "mimes check : " << text_mime[i] << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
	   }
#endif
        }
   }
#ifdef E2DEBUG
             std::cerr << thread_id << "mimes result : " << "false" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
   return false;
}

// grab contents of X-Forwarded-For header
// Modification based on a submitted patch by
// Jimmy Myrick (jmyrick@tiger1.tiger.org)
std::string HTTPHeader::getXForwardedForIP()
{
    if (pxforwardedfor != NULL) {
        String line(pxforwardedfor->after(": "));
        line.chop();
        return std::string(line.toCharArray());
    }
    return "";
}

// check the return code to see if it's a redirection request
bool HTTPHeader::isRedirection()
{
    // The 1st line of the header for a redirection is thus:
    // HTTP/1.(0|1) 3xx
    if (header.size() < 1) {
        return false;
    } // sometimes get called b 4 read
    String answer(header.front().after(" ").before(" "));
    if (answer[0] == '3' && answer.length() == 3) {
        return true;
    }
    return false;
}

// grab the contents of Proxy-Authorization header
// returns base64-decoding of the chunk of data after the auth type string
std::string HTTPHeader::getAuthData()
{
    if (pproxyauthorization != NULL) {
        String line(pproxyauthorization->after(" ").after(" "));
        return decodeb64(line); // it's base64 MIME encoded
    }
    return "";
}

std::string HTTPHeader::getAuthHeader()
{
    if (pheaderident != NULL) {
        String line (pheaderident->after(" "));
        line.resize(line.length() - 1);
        return line;
    }
    return "";
}

// grab raw contents of Proxy-Authorization header without decoding
std::string HTTPHeader::getRawAuthData()
{
    if (pproxyauthorization != NULL) {
        return pproxyauthorization->after(" ").after(" ");
    }
    return "";
}

// do we have a non-identity content encoding? this means body is compressed
bool HTTPHeader::isCompressed()
{
    if (pcontentencoding != NULL) {
        if (pcontentencoding->indexOf("identity") != -1) {
            // http says this
            // should not be here, but not must not
            return false;
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "is compressed" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return true; // i.e. encoded with something other than clear
    }
    return false;
}

// grab content encoding header
String HTTPHeader::contentEncoding()
{
    if (pcontentencoding != NULL) {
        String ce(pcontentencoding->after(": "));
        ce.toLower();
        return ce;
    }
    return ""; // we need a default don't we?
}

// grab transfer encoding header
String HTTPHeader::transferEncoding()
{
    if (ptransferencoding != NULL) {
        String ce(ptransferencoding->after(": "));
        ce.toLower();
        return ce;
    }
    return ""; // we need a default don't we?
}

// *
// *
// * header modifications
// *
// *

// squid adds this so if more support it it may be useful one day
void HTTPHeader::addXForwardedFor(const std::string &clientip)
{
    if (!isdirect) {
        std::string line("X-Forwarded-For: " + clientip + "\r");
        header.push_back(String(line.c_str()));
    }
}

// set content length header to report given lenth
void HTTPHeader::setContentLength(int newlen)
{
    if (pcontentlength != NULL) {
        (*pcontentlength) = "Content-Length: " + String(newlen) + "\r";
    }
    contentlength = newlen;
    clcached = true;
}

// set the proxy-connection header to allow persistence (or not)
void HTTPHeader::makePersistent(bool persist)
{
    if (persist) {
        // Only make persistent if it originally was, but now isn't.
        // The intention isn't to change browser behaviour, just to
        // un-do any connection downgrading which E2 may have performed
        // earlier.
        if (waspersistent && !ispersistent) {
            if (pproxyconnection != NULL) {
                (*pproxyconnection) = pproxyconnection->before(":") + ": keep-alive\r";
            } else {
                header.push_back(String("Connection: keep-alive\r"));
                pproxyconnection = &(header.back());
            }
            ispersistent = true;
        }
    } else {
        // Only downgrade to non-persistent if it isn't currently persistent.
        if (ispersistent) {
            if (pproxyconnection != NULL) {
                (*pproxyconnection) = pproxyconnection->before(":") + ": close\r";
            } else {
                header.push_back(String("Connection: close\r"));
                pproxyconnection = &(header.back());
            }
            ispersistent = false;
        }
    }
}

// make the request look like it's come from/to the origin server
void HTTPHeader::makeTransparent(bool incoming)
{
#ifdef E2DEBUG
    std::cerr << thread_id << "Making headers transparent" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    if (incoming) {
        // remove references to the proxy before sending to browser
        if (pproxyconnection != NULL) {
            String temp = pproxyconnection->after(":");
            (*pproxyconnection) = "Connection:";
            (*pproxyconnection) += temp;
        }
        if (pproxyauthenticate != NULL) {
            String temp = pproxyauthenticate->after(":");
            (*pproxyauthenticate) = "WWW-Authenticate:";
            (*pproxyauthenticate) += temp;
        }
        if (returnCode() == 407) {
            String temp = header.front().before(" ");
            String temp2 = header.front().after(" ").after(" ");
            header.front() = temp + " 401 ";
            header.front() += temp2;
        }
    } else {
        // remove references to origin server before sending to proxy
        if (pauthorization != NULL) {
            String temp = pauthorization->after(":");
            (*pauthorization) = "Proxy-Authorization:";
            (*pauthorization) += temp;
            pproxyauthorization = pauthorization;
            pauthorization = NULL;
        }
        if (pproxyconnection != NULL) {
            String temp = pproxyconnection->after(":");
            (*pproxyconnection) = "Connection:";
            (*pproxyconnection) += temp;
        }
        // call this to fudge the URL into something Squid likes
        getUrl();
    }
}

// return a modified accept-encoding header, based on the one supplied,
// but with "identity" added and only supported encodings allowed.
String HTTPHeader::modifyEncodings(String e)
{

    // There are 4 types of encoding: gzip, deflate, compress and identity
    // deflate is in zlib format
    // compress is in unix compress format
    // identity is uncompressed and supported by all browsers (obviously)
    // we do not support compress

    e.toLower();
    String o("Accept-Encoding: identity");
#if ZLIB_VERNUM < 0x1210
#warning 'Accept-Encoding: gzip' is disabled
#else
    if (e.contains("gzip")) {
        o += ",gzip";
    }
#endif
    if (e.contains("deflate")) {
        o += ",deflate";
    }

    if (e.contains("pack200-gzip")) {
        o += ",pack200-gzip";
    }

    return o;
}

// set content length to report the given length, and strip content encoding
void HTTPHeader::removeEncoding(int newlen)
{
    if (pcontentlength != NULL) {
        (*pcontentlength) = "Content-Length: " + String(newlen) + "\r";
    }
    // this may all be overkill. since we strip everything out of the outgoing
    // accept-encoding header that we don't support, we won't be getting anything
    // back again that we don't support, in theory. leave new code commented
    // unless it proves to be necessary further down the line. PRA 20-10-2005
    if (pcontentencoding != NULL) {
        /*#ifdef E2DEBUG
		std::cerr << std::endl << "Stripping Content-Encoding header" <<std::endl;
		std::cerr << "Old: " << header[i] <<std::endl;
#endif
		// only strip supported compression types
		String temp(header[i].after(":"));
		temp.removeWhiteSpace();
		String newheader;
		// iterate over comma-separated list of encodings
		while (temp.length() != 0) {
			if (!(temp.startsWith("gzip") || temp.startsWith("deflate"))) {
				// add other, unstripped encoding types back into the header
				if (newheader.length() != 0)
					newheader += ", ";
				newheader += (temp.before(",").length() != 0 ? temp.before(",") : temp);
			}
			temp = temp.after(",");
			temp.removeWhiteSpace();
		}
		if (newheader.length() == 0)*/
        (*pcontentencoding) = "X-DansGuardian-Removed: Content-Encoding\r";
        /*			else
			header[i] = "Content-Encoding: "+newheader;
#ifdef E2DEBUG
		std::cerr << "New: " << header[i] << std::endl << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif*/
    }
}

// modifies the URL in all relevant header lines after a regexp search and replace
// setURL Code originally from from Ton Gorter 2004
void HTTPHeader::setURL(String &url)
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

#ifdef E2DEBUG
    std::cerr << thread_id << "setURL: header.front() changed from: " << header.front() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    if (https && header.front().startsWith("CONNECT"))
        // Should take form of "CONNECT example.com:443 HTTP/1.0" for SSL
        header.front() = header.front().before(" ") + " " + hostname + ":" + String(port) + " " + header.front().after(" ").after(" ");
    else
        header.front() = header.front().before(" ") + " " + url + " " + header.front().after(" ").after(" ");
#ifdef E2DEBUG
    std::cerr << thread_id << " to: " << header.front() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    if (phost != NULL) {
#ifdef E2DEBUG
        std::cerr << thread_id << "setURL: header[] line changed from: " << (*phost) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        (*phost) = String("Host: ") + hostname;
        if (port != (https ? 443 : 80)) {
            (*phost) += ":";
            (*phost) += String(port);
        }
        (*phost) += "\r";
#ifdef E2DEBUG
        std::cerr << thread_id << " to " << (*phost) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    }
    if (pport != NULL) {
#ifdef E2DEBUG
        std::cerr << thread_id << "setURL: header[] line changed from: " << (*pport) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        (*pport) = String("Port: ") + String(port) + "\r";
#ifdef E2DEBUG
        std::cerr << thread_id << " to " << (*pport) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    }
    // Don't just cache the URL we're sent - getUrl() performs some other
    // processing, notably stripping the port part. Caching here will
    // bypass all that.
    //cachedurl = url.toCharArray();
    cachedurl = "";   // blank cachedurl so that getUrl will re-generate it
}

// Does a regexp search and replace.
// urlRegExp Code originally from from Ton Gorter 2004
bool HTTPHeader::regExp(String &line, std::deque<RegExp> &regexp_list, std::deque<String> &replacement_list)
{
    RegExp *re;
    RegResult Rre;
    String replacement;
    String repstr;
    String newLine;
    bool linemodified = false;
    unsigned int i;
    unsigned int j, k;
    unsigned int s = regexp_list.size();
    unsigned int matches, submatches;
    unsigned int match;
    unsigned int srcoff;
    unsigned int nextoffset;
    unsigned int matchlen;
    unsigned int oldlinelen;

    if ( (line.empty())  || line.length() < 3)
        return false;

    // iterate over our list of precompiled regexes
    for (i = 0; i < s; i++) {
        newLine = "";
        re = &(regexp_list[i]);
        if (re->match(line.toCharArray(), Rre)) {
            repstr = replacement_list[i];
            matches = Rre.numberOfMatches();

            srcoff = 0;

            for (j = 0; j < matches; j++) {
                nextoffset = Rre.offset(j);
                matchlen = Rre.length(j);

                // copy next chunk of unmodified data
                if (nextoffset > srcoff) {
                    newLine += line.subString(srcoff, nextoffset - srcoff);
                    srcoff = nextoffset;
                }

                // Count number of submatches (brackets) in replacement string
                for (submatches = 0; j + submatches + 1 < matches; submatches++)
                    if (Rre.offset(j + submatches + 1) + Rre.length(j + submatches + 1) > srcoff + matchlen)
                        break;

                // \1 and $1 replacement
                replacement = "";
                for (k = 0; k < repstr.length(); k++) {
                    // find \1..\9 and $1..$9 and fill them in with submatched strings
                    if ((repstr[k] == '\\' || repstr[k] == '$') && repstr[k + 1] >= '1' && repstr[k + 1] <= '9') {
                        match = repstr[++k] - '0';
                        if (match <= submatches) {
                            replacement += Rre.result(j + match).c_str();
                        }
                    } else {
                        // unescape \\ and \$, and add non-backreference characters to string
                        if (repstr[k] == '\\' && (repstr[k + 1] == '\\' || repstr[k + 1] == '$'))
                            k++;
                        replacement += repstr.subString(k, 1);
                    }
                }

                // copy filled in replacement string
                newLine += replacement;
                srcoff += matchlen;
                j += submatches;
            }
            oldlinelen = line.length();
            if (srcoff < oldlinelen) {
                newLine += line.subString(srcoff, oldlinelen - srcoff);
            }
#ifdef E2DEBUG
            std::cerr << thread_id << "Line modified! (" << line << " -> " << newLine << ")" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            // copy newLine into line and continue with other regexes
            line = newLine;
            linemodified = true;
        }
    }

    return linemodified;
}



String HTTPHeader::redirecturl()
{
    return redirect;
}

bool HTTPHeader::addHeader(String &newheader) {
    if (newheader.size() > 0) {
    isheaderadded = true;
    addheaderchecked = true;
    std::string line(newheader + "\r");
    header.push_back(String(line.c_str()));
#ifdef E2DEBUG
    std::cerr << thread_id << "addheader = " << newheader << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return true;
        }
    return false;
}


void HTTPHeader::setPostData(const char *data, size_t len)
{
    delete postdata;
    postdata = new char[len];
    memcpy(postdata, data, len);
    postdata_len = len;
}

// *
// *
// * detailed header checks & fixes
// *
// *

// is a URL malformed?
bool HTTPHeader::malformedURL(const String &url)
{
    String host(url.after("://"));
    if (host.contains("/"))
        host = host.before("/");
    if (host.length() < 2) {
#ifdef E2DEBUG
        std::cerr << thread_id << "host len too small" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return true;
    }
    if (host.contains(":"))
        host = host.before(":");
    // endsWith . check removed as this format is used by Apple Configurator Updates
    //	if (host.contains("..") || host.endsWith(".")) {
    if (host.contains("..")) {
#ifdef E2DEBUG
        std::cerr << thread_id << "double dots in domain name" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return true;
    }
    int i, len;
    unsigned char c;
    len = host.length();
    bool containsletter = false;
    for (i = 0; i < len; i++) {
        c = (unsigned char)host[i];
        // If it contains something other than numbers, dots, or [a-fx] (hex encoded IPs),
        // IP obfuscation can be ruled out.
        if (!containsletter && (((c < '0') || (c > '9'))
                                   && (c != '.') && (c != 'x') && (c != 'X')
                                   && ((c < 'a') || (c > 'f'))
                                   && ((c < 'A') || (c > 'F'))))
            containsletter = true;
        if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z')
            && !(c >= '0' && c <= '9') && c != '.' && c != '-' && c != '_') {
#ifdef E2DEBUG
            std::cerr << thread_id << "bad char in hostname" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            return true;
            // only allowed letters, digits, hiphen, dots
        }
    }
    // no IP obfuscation going on
    if (containsletter)
        return false;
#ifdef E2DEBUG
    else
        std::cerr << thread_id << "Checking for IP obfuscation in " << host << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    // Check no IP obfuscation is going on
    // This includes IPs encoded as a single decimal number,
    // fully or partly hex encoded, and octal encoded
    bool first = true;
    bool obfuscation = false;
    if (host.endsWith("."))
        host.chop();
    do {
        if (!first)
            host = host.after(".");
        first = false;
        String hostpart(host);
        if (host.contains("."))
            hostpart = hostpart.before(".");
        // If any part of the host starts with a letter, any letter,
        // then we must have a hostname rather than an IP (obscured
        // or otherwise).  TLDs never start with a number.
        if ((hostpart[0] >= 'a' && hostpart[0] <= 'z') || (hostpart[0] >= 'A' && hostpart[0] <= 'Z'))
            return false;
        // If any part of the host begins with 0, it may be hex or octal
        if ((hostpart[0] == '0') && (hostpart.length() > 1)) {
            obfuscation = true;
            continue;
        }
        // Also check range, for decimal obfuscation.
        int part = hostpart.toInteger();
        if ((part < 0) || (part > 255))
            obfuscation = true;
    } while (host.contains("."));
    // If we have any obfuscated parts, and haven't proven it's a hostname, it's invalid.
    return obfuscation;
}


// Show headers values for debug purpose

void HTTPHeader::dbshowheader(String *url, const char *clientip)
{
    return;   // temporally disable
    std::string reqres, inout;
    if (is_response) {
        reqres = "RES";
    } else {
        reqres = "REQ";
    }
    //std::hash<std::thread::id> htid;
//    std::thread::id tid = std::this_thread::get_id();
//    std::size_t tid = htid(std::this_thread::get_id());
    const char *tid = thread_id.c_str();

	if (header.size() != 0){
        String *line;
        syslog(LOG_INFO, "%s Client: %s START  %s -------------------------------", tid, clientip, reqres.c_str());
#ifdef E2DEBUG
            std::cerr << thread_id  << "Client: START " << reqres << "-------------------------------" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
        for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
            line = &(*i);
            String line2 = *line;
            if (header.front().startsWith("HT")) {
                inout = "IN";
            } else {
                inout = "OUT";
            }
                syslog(LOG_INFO, "%s: %s: Client IP at %s header: %s", tid, inout.c_str(), clientip, line2.c_str());
#ifdef E2DEBUG
            std::cerr << thread_id  << inout << ": Client IP " << clientip << " "<< line2.c_str() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
            }
            syslog(LOG_INFO, "%s: Client: %s END %s -------------------------------", tid, clientip, reqres.c_str());
#ifdef E2DEBUG
        std::cerr << thread_id  << "Client: END " << reqres << " -------------------------------" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
    } else {
            syslog(LOG_INFO, "%s: Client: %s Call to dbshowheader but %s header is empty", tid, clientip, reqres.c_str());
#ifdef E2DEBUG
            std::cerr << thread_id  << "Call : from HTTPHeader.cpp to dbshowheader but" << reqres << " header is empty" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
    }
}

void HTTPHeader::dbshowheader(bool outgoing)
{
    return;   // temporally disable
    std::string reqres, inout;
    if (is_response) {
        reqres = "RES";
    } else {
        reqres = "REQ";
    }
    if (outgoing)
        inout = reqres + "OUT";
    else
        inout = reqres + "IN";

    std::hash<std::thread::id> htid;
//    std::thread::id tid = std::this_thread::get_id();
    std::size_t tid = htid(std::this_thread::get_id());

    if (header.size() != 0){
        String *line;
        syslog(LOG_INFO, "Client: START-------------------------------");
#ifdef E2DEBUG
            std::cerr << thread_id << "Client: START-------------------------------" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
        for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
            line = &(*i);
            String line2 = *line;
                syslog(LOG_INFO, "%lu:%s: dbshowheader bool - header: %s", tid, inout.c_str(), line2.c_str());
#ifdef E2DEBUG
            std::cerr << thread_id  << inout <<": dbshowheader bool: " << line2.c_str() << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
        }
        syslog(LOG_INFO, "Client: END-------------------------------");
#ifdef E2DEBUG
        std::cerr << thread_id << "Client: END-------------------------------" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
    } else {
            syslog(LOG_INFO, "%lu:Call : from HTTPHeader.cpp to dbshowheader but header is empty", tid);
#ifdef E2DEBUG
            std::cerr << thread_id << "Call : from HTTPHeader.cpp to dbshowheader but header is empty" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;;
#endif
    }
}



// fix bugs in certain web servers that don't obey standards.
// actually, it's us that don't obey standards - HTTP RFC says header names
// are case-insensitive. - Anonymous SF Poster, 2006-02-23
void HTTPHeader::checkheader(bool allowpersistent)
{
    bool outgoing = !is_response;
//    if (header.front().startsWith("HT")) {
//        outgoing = false;
//    }
    String tp;

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
        } else if (outgoing && (puseragent == NULL) && i->startsWithLower("user-agent:")) {
            puseragent = &(*i);
             useragent = *i;
             if(!useragent.headerVal())
                 puseragent = NULL;
        } else if (outgoing && i->startsWithLower("accept-encoding:")) {
            (*i) = "Accept-Encoding:" + i->after(":");
            (*i) = modifyEncodings(*i) + "\r";
        } else if ((!outgoing) && (pcontentencoding == NULL) && i->startsWithLower("content-encoding:")) {
            pcontentencoding = &(*i);
        } else if ((!outgoing) && (pkeepalive == NULL) && i->startsWithLower("keep-alive:")) {
            pkeepalive = &(*i);
        } else if ((pcontenttype == NULL) && i->startsWithLower("content-type:")) {
            pcontenttype = &(*i);
        } else if ((pcontentlength == NULL) && i->startsWithLower("content-length:")) {
            pcontentlength = &(*i);
        tp = *i;
#ifdef E2DEBUG
        std::cerr << thread_id << "tp =" << tp << std::endl;
#endif
        if(!tp.headerVal())
            pcontentlength = NULL;
        else {
            contentlength = tp.toInteger();
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "tp =" << tp << " Contentlen.int =" << contentlength << std::endl;
#endif

        }
        // is this ever sent outgoing?
        else if ((pcontentdisposition == NULL) && i->startsWithLower("content-disposition:")) {
            pcontentdisposition = &(*i);
        } else if ((pproxyauthorization == NULL) && i->startsWithLower("proxy-authorization:")) {
            pproxyauthorization = &(*i);
        } else if ((pauthorization = NULL) && i->startsWithLower("authorization:")) {
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
    } else if ( i->startsWithLower("transfer-encoding:")) {
        ptransferencoding = &(*i);
        if (i->contains("chunked"))
            chunked = true;
    } else if ( i->startsWithLower("transfer-coding:")) {
        ptransfercoding = &(*i);
    } else if ( i->startsWithLower("expect: 100-continue")) {
	    expects_100 = true;
        }

	//Can be placed anywhere ..
        if (outgoing && i->startsWithLower("upgrade-insecure-requests:")) {
            i->assign("X-E2G-IgnoreMe: removed upgrade-insecure-requests\r");
        }

   //     if ((o.log_header_value.size() != 0) && outgoing && (plogheadervalue == NULL) && i->startsWithLower(o.log_header_value)) {
    //        plogheadervalue = &(*i);
     //   }
        if ((o.ident_header_value.size() != 0) && outgoing && (pheaderident == NULL) && i->startsWithLower(o.ident_header_value)) {
            pheaderident = &(*i);
        }

#ifdef E2DEBUG
        std::cerr << thread_id << "Header value from client: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    }
}

    //if its http1.1
    bool onepointone = false;
    if (header.front().after("HTTP/").startsWith("1.1")) {
#ifdef E2DEBUG
        std::cerr << thread_id << "CheckHeader: HTTP/1.1 detected" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        onepointone = true;
    }

    if (outgoing) {        // set request Type
        requesttype = header.front().before(" ");
        if (!requesttype.startsWith("P"))   // is not POST or PUT no body is allowed
        {
#ifdef E2DEBUG
            std::cerr << thread_id << "zero contentlength on request due to not POST/PUT " << std::endl;
#endif
            contentlength = 0;
        }
        if(header.front().after(" ").startsWith("/"))
            isProxyRequest = false;
        else
            isProxyRequest = true;
    } else {                    // set status code
        tp = header.front().after(" ").before(" ");
        tp.removeWhiteSpace();
        returncode = tp.toInteger();
        if ((returncode < 200) || (returncode == 204) || (returncode == 304))    // no content body allowed
        {
#ifdef E2DEBUG
            std::cerr << thread_id << "zero contentlength on response due to returncode " << returncode << std::endl;
#endif
            contentlength = 0;
        }
    }

    //work out if we should explicitly close this connection after this request
    bool connectionclose = false;
    if(!icap) {
        if (pproxyconnection != NULL) {
            if (pproxyconnection->contains("lose")) {
#ifdef E2DEBUG
                std::cerr << thread_id << "CheckHeader: P-C says close" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                connectionclose = true;
            } else {
                connectionclose = false;
            }
        } else {
            connectionclose = true;
        }
    }

    // Do not allow persistent connections on CONNECT requests - the browser thinks it has a tunnel
    // directly to the external server, not a connection to the proxy, so it won't be re-used in the
    // manner expected by E2 and will result in waiting for time-outs.  Bug identified by Jason Deasi.
    bool isconnect = false;
    if (outgoing && header.front()[0] == 'C') {
#ifdef E2DEBUG
        std::cerr << thread_id << "CheckHeader: CONNECT request detected" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        isconnect = true;
    }

#ifdef E2DEBUG
    std::cerr << thread_id << "CheckHeader flags before normalisation: AP=" << allowpersistent << " PPC=" << (pproxyconnection != NULL)
              << " 1.1=" << onepointone << " connectionclose=" << connectionclose << " CL=" << (pcontentlength != NULL) << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    if (connectionclose || (!onepointone && (outgoing ? isconnect : (pcontentlength == NULL)))) {
        // couldnt have done persistency even if we wanted to
        allowpersistent = false;
    }

    if(!icap) {
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
    }

#ifdef E2DEBUG
    std::cerr << thread_id << "CheckHeader flags after normalisation: AP=" << allowpersistent << " WP=" << waspersistent << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

if(!icap) {
    // force the headers to reflect whether or not persistency is allowed
    // (modify pproxyconnection or add connection close/keep-alive - Client version, of course)
    if (allowpersistent) {
        if (pproxyconnection == NULL) {
#ifdef E2DEBUG
            std::cerr << thread_id << "CheckHeader: Adding our own Proxy-Connection: Keep-Alive" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            header.push_back("Connection: keep-alive\r");
            pproxyconnection = &(header.back());
        } else {
            (*pproxyconnection) = "Connection: keep-alive\r";
        }
    } else {
        if (pproxyconnection == NULL) {
#ifdef E2DEBUG
            std::cerr << thread_id << "CheckHeader: Adding our own Proxy-Connection: Close" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            header.push_back("Connection: close\r");
            pproxyconnection = &(header.back());
        } else {
            (*pproxyconnection) = "Connection: close\r";
        }
    }
}

    ispersistent = allowpersistent;

    // Normalise request headers (fix host, port, first line of header, etc. to all be consistent)
    if (outgoing) {
        String newurl(getUrl(true));
        setURL(newurl);
    }
}

String HTTPHeader::getLogUrl(bool withport, bool isssl)
{

    String answer = getUrl(withport, isssl);
    if (mitm || isssl) {
        answer = "https://" + answer.after("://");
    }
    return answer;
}

String HTTPHeader::getUrl(bool withport, bool isssl)
{
    // Version of URL *with* port is not cached,
    // as vast majority of our code doesn't like
    // port numbers in URLs.
    if (cachedurl.length() > 0 && !withport)
        return cachedurl;
    port = 80;
    bool https = false;
    if (isssl) {
        mitm = isssl;
        isdirect = true;
    }

    if ( header.size() == 0)
    {
        String ans;
        return ans;
    }

    String hostname;
    String userpassword;
    String answer(header.front().after(" "));
    answer.removeMultiChar(' ');
    if (answer.after(" ").startsWith("HTTP/")) {
        answer = answer.before(" HTTP/");
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
                if (withport && (port != (https ? 443 : 80)))
                    hostname += ":" + String(port);
                hostname = "http://" + hostname;
                answer = hostname + answer;
            }
            // Squid doesn't like requests in this format. Work around the fact.
            header.front() = requestType() + " " + answer + " HTTP/" + header.front().after(" HTTP/");
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
            if (withport && (port != (https ? 443 : 80)))
                hostname += ":" + String(port);
            if (userpassword.length())
                answer = protocol + "://" + userpassword + "@" + hostname + url;
            else
                answer = protocol + "://" + hostname + url;
        }
    }
//  Some sites do now have urls ending with '//' and will not answer to just '/'
//	if (answer.endsWith("//")) {
//		answer.chop();
//	}

#ifdef E2DEBUG
    std::cerr << thread_id << "from header url:" << answer << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    // Don't include port numbers in the URL in the cached version.
    // Most of the code only copes with URLs *without* port specifiers.
    if (!withport)
        cachedurl = answer.toCharArray();
    return answer;
}

String HTTPHeader::url()
{
    return getUrl();
}

// *
// *
// * Bypass URL/Cookie funcs
// *
// *

// chop the GBYPASS or GIBYPASS variable out of a bypass URL
// This function ASSUMES that you really know what you are doing
// Do NOT run this function unless you know that the URL contains a valid bypass code
// Ernest W Lessenger
void HTTPHeader::chopBypass(String url, bool infectionbypass)
{
    if (url.contains(infectionbypass ? "GIBYPASS=" : "GBYPASS=")) {
        if (url.contains(infectionbypass ? "?GIBYPASS=" : "?GBYPASS=")) {
            String bypass(url.after(infectionbypass ? "?GIBYPASS=" : "?GBYPASS="));
            header.front() = header.front().before(infectionbypass ? "?GIBYPASS=" : "?GBYPASS=") + header.front().after(bypass.toCharArray());
        } else {
            String bypass(url.after(infectionbypass ? "&GIBYPASS=" : "&GBYPASS="));
            header.front() = header.front().before(infectionbypass ? "&GIBYPASS=" : "&GBYPASS=") + header.front().after(bypass.toCharArray());
        }
    }
    cachedurl = "";
}

// same for scan bypass
void HTTPHeader::chopScanBypass(String url)
{
    if (url.contains("GSBYPASS=")) {
        if (url.contains("?GSBYPASS=")) {
            String bypass(url.after("?GSBYPASS="));
            header.front() = header.front().before("?GSBYPASS=") + header.front().after(bypass.toCharArray());
        } else {
            String bypass(url.after("&GSBYPASS="));
            header.front() = header.front().before("&GSBYPASS=") + header.front().after(bypass.toCharArray());
        }
    }
    cachedurl = "";
}


// I'm not proud of this... --Ernest
String HTTPHeader::getCookie(const char *cookie)
{
    String line;
    // TODO - do away with loop here somehow, or otherwise speed it up?
    for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
        if (i->startsWithLower("cookie:")) {
            line = i->after(": ");
            if (line.contains(cookie)) { // We know we have the cookie
                line = line.after(cookie);
                line.lop(); // Get rid of the '='
                if (line.contains(";")) {
                    line = line.before(";");
                }
            }
            // break;  // Technically there should be only one Cookie: header, but...
        }
    }
    line.removeWhiteSpace();
#ifdef E2DEBUG
    std::cerr << thread_id << "Found cookie:" << line << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    return line;
}

// add cookie with given name & value to outgoing headers
void HTTPHeader::setCookie(const char *cookie, const char *domain, const char *value)
{
    String line("Set-Cookie: ");
    line += cookie;
    line += "=";
    line += value;
    line += "; path=/; domain=.";
    line += domain;
    line += "\r";
    header.push_back(line);
#ifdef E2DEBUG
    std::cerr << thread_id << "Setting cookie:" << line << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    // no expiry specified so ends with the browser session
}

// is this a temporary filter bypass cookie?
bool HTTPHeader::isBypassCookie(String url, const char *magic, const char *clientip, const char *user)
{
    String cookie(getCookie("GBYPASS"));
    if (!cookie.length()) {
#ifdef E2DEBUG
        std::cerr << thread_id << "No bypass cookie" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return false;
    }
    String cookiehash(cookie.subString(0, 32));
    String cookietime(cookie.after(cookiehash.toCharArray()));
    String mymagic(magic);
    mymagic += clientip;
    mymagic += user;
    mymagic += cookietime;
    bool matched = false;
    while (url.contains(".")) {
        String hashed(url.md5(mymagic.toCharArray()));
#ifdef E2DEBUG
        std::cerr << thread_id << "Bypass cookie:" << cookiehash << " hashed: " << hashed << " contains " << clientip << " " << user << " " << url << " " << cookietime << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        if (hashed == cookiehash) {
            matched = true;
            break;
        }
        url = url.after(".");
    }
    if (not matched) {
#ifdef E2DEBUG
        std::cerr << thread_id << "Cookie GBYPASS not match" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return false;
    }
    time_t timen = time(NULL);
    time_t timeu = cookietime.toLong();
    if (timeu < timen) {
#ifdef E2DEBUG
        std::cerr << thread_id << "Cookie GBYPASS expired: " << timeu << " " << timen << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return false;
    }
    return true;
}

String HTTPHeader::getReferer()
{
    String line;
    for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
        if (i->startsWithLower("referer:")) {
            line = i->after(": ");
            break;
        }
    }
    line.removeWhiteSpace();
#ifdef E2DEBUG
    std::cerr << thread_id << "Found Referer URL:" << line << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    return line;
}

// *
// *
// * URL and Base64 decoding funcs
// *
// *

// URL decoding (%xx)
// uses regex pre-compiled on startup
String HTTPHeader::decode(const String &s, bool decodeAll)
{
    if (s.length() < 3) {
        return s;
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "decoding url" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    RegResult Rre;
    if (!urldecode_re.match(s.c_str(),Rre)) {
        return s;
    } // exit if not found
#ifdef E2DEBUG

    std::cerr << thread_id << "removing %XX" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    int match;
    int offset;
    int pos = 0;
    int size = s.length();
    String result;
    String n;
    for (match = 0; match < Rre.numberOfMatches(); match++) {
        offset = Rre.offset(match);
        if (offset > pos) {
            result += s.subString(pos, offset - pos);
        }
        n = Rre.result(match).c_str();
        n.lop(); // remove %
        result += hexToChar(n, decodeAll);
#ifdef E2DEBUG
        std::cerr << thread_id << "encoded: " << Rre.result(match) << " decoded: " << hexToChar(n) << " string so far: " << result << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        pos = offset + 3;
    }
    if (size > pos) {
        result += s.subString(pos, size - pos);
    } else {
        n = "%" + n;
    }
    return result;
}

// turn %xx back into original character
String HTTPHeader::hexToChar(const String &n, bool all)
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
std::string HTTPHeader::decodeb64(const String &line)
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
int HTTPHeader::decode1b64(char c)
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
// * encode funcs
// *

// get encoded URL?
String HTTPHeader::URLEncode()
{
    std::string encoded;
    String newurl(getUrl());
    const char *s = newurl.c_str();
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
    String returnS(encoded);
    return returnS;
}

String HTTPHeader::stringHeader() {
    String l;
#ifdef E2DEBUG
    std::cerr << thread_id << "stringHeader started hsize=" << header.size() << std::endl;
#endif
    if (header.size() > 0) {
        for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
            if (! (*i).startsWith("X-E2G-IgnoreMe")){
#ifdef E2DEBUG
                std::cerr << thread_id << "Found Header: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                l += (*i) + "\n";
            }
#ifdef E2DEBUG
            else {
                    std::cerr << thread_id << "Found Header X-E2G-IgnoreMe: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
            }
#endif
        }
        l += "\r\n";
    }
    return l;
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
//void HTTPHeader::out(Socket *peersock, Socket *sock, int sendflag, bool reconnect) throw(std::exception)
bool HTTPHeader::out(Socket *peersock, Socket *sock, int sendflag, bool reconnect )
{
    String l; // for amalgamating to avoid conflict with the Nagel algorithm

    if (sendflag == __E2HEADER_SENDALL || sendflag == __E2HEADER_SENDFIRSTLINE) {
        if (header.size() > 0) {
            l = header.front() + "\n";

#ifdef E2DEBUG
            if(is_response)  {
    std::cerr << thread_id << "response headerout:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
    } else {
    std::cerr << thread_id << "request headerout:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
    }
#endif

#ifdef __SSLMITM
            //if a socket is ssl we want to send relative paths not absolute urls
            //also HTTP responses dont want to be processed (if we are writing to an ssl client socket then we are doing a request)
            if (sock->isSsl() && !sock->isSslServer()) {
                setDirect();
            }
#endif

            if (isdirect && !is_response) {
                l = header.front().before(" ") + " /" + header.front().after("://").after("/").before(" ") + " HTTP/1.1\r\n";
#ifdef E2DEBUG
    std::cerr << thread_id << "request headerout (modified for direct):" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            }

            // first reconnect loop - send first line
            while (true) {
                if (!sock->writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
                    // reconnect & try again if we've been told to
                    if (reconnect && !isdirect) {
// don't try more than once
#ifdef E2DEBUG
                        std::cerr << thread_id << "Proxy connection broken (1); trying to re-establish..." << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
                        syslog(LOG_ERR, "Proxy connection broken (1); trying to re-establish...");
#endif
                        reconnect = false;
                        sock->reset();
                        int rc = sock->connect(o.proxy_ip, o.proxy_port);
                        if (rc)
                            return false;
//                            throw std::exception();
                        continue;
                    }
                    // throw std::exception();
                    return false;
                }
                // if we got here, we succeeded, so break the reconnect loop
#ifdef E2DEBUG
                std::cerr << thread_id << "headertoclient:" << l << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
                std::cerr << thread_id << "timeout:" << timeout << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                break;
            }
        }
        if (sendflag == __E2HEADER_SENDFIRSTLINE) {
            return true;
        }
    }

    l = "";

    if (header.size() > 1) {
        for (std::deque<String>::iterator i = header.begin() + 1; i != header.end(); i++) {
            if (! (*i).startsWith("X-E2G-IgnoreMe")){
#ifdef E2DEBUG
                std::cerr << thread_id << "Found Header: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                l += (*i) + "\n";
            }
#ifdef E2DEBUG
            else {
                    std::cerr << thread_id << "Found Header X-E2G-IgnoreMe: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
            }
#endif
        }

    }
    if (!is_response && o.forwarded_for && !isdirect)  {
        std::string line("X-Forwarded-For: ");
        line.append(s_clientip).append("\r\n");
#ifdef E2DEBUG
        std::cerr << thread_id << "Adding Header: " << line << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
       l += line;
    }
    l += "\r\n";

    // second reconnect loop
    while (true) {
        // send header to the output stream
        // need exception for bad write

        if (!sock->writeToSocket(l.toCharArray(), l.length(), 0, timeout)) {
            // reconnect & try again if we've been told to
            if (reconnect && !isdirect) {
// don't try more than once
#ifdef E2DEBUG
                std::cerr << thread_id << "Proxy connection broken (2); trying to re-establish..." << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
                syslog(LOG_ERR, "Proxy connection broken (2); trying to re-establish...");
#endif
                reconnect = false;
                sock->reset();
                int rc = sock->connect(o.proxy_ip, o.proxy_port);
                if (rc)
                    return false;
               //     throw std::exception();
                // include the first line on the retry
                l = header.front() + "\n" + l;
                continue;
            }
            //throw std::exception();
            return false;
        }
        // if we got here, we succeeded, so break the reconnect loop
        break;
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "Header written - pstdata_len:" << postdata_len << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    if (postdata_len > 0) {
#ifdef E2DEBUG
        std::cerr << thread_id << "Sending manually set POST data" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        if (!sock->writeToSocket(postdata, postdata_len, 0, timeout)) {
#ifdef E2DEBUG
            std::cerr << thread_id << "Could not send POST data!" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            //throw std::exception();
            return false;
        }
    } else if ((peersock != NULL) && (!requestType().startsWith("HTTP")) && (pcontentlength != NULL)) {
#ifdef E2DEBUG
        std::cerr << thread_id << "Opening tunnel for POST data" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        FDTunnel fdt;
        if (!fdt.tunnel(*peersock, *sock, false, contentLength(), true) )
            return false;
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "Returning from header:out " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
    dbshowheader(true);
#endif
    return true;
}

// discard remainder of POST data
void HTTPHeader::discard(Socket *sock, off_t cl)
{
    static char header[4096];
    if (cl == -2)
        cl = contentLength();
    int rc;
    while (cl > 0) {
        rc = sock->readFromSocket(header, ((cl > 4096) ? 4096 : cl), 0, timeout, false);
        if (rc > 0)
            cl -= rc;
        else
            break;
    }
}

void HTTPHeader::setClientIP(String &ip) {
    s_clientip = ip.toCharArray();
}

String HTTPHeader::getClientIP() {
    return s_clientip;
}

void HTTPHeader::setDirect() {
    isdirect = true;
}

bool HTTPHeader::in_handle_100(Socket *sock, bool allowpersistent, bool expect_100) {
    int max_100s = 4;
    while( max_100s > 0)
    {
        if( in(sock,allowpersistent)) {
            if (!expect_100 && returncode == 100) // discard 100 continue header and get next header
            {
                max_100s--;
                continue;
            } else {
                return true;
            }
        } else {
            return false;
        }
    }
    return false;
}

bool HTTPHeader::in(Socket *sock, bool allowpersistent)
{
    if (dirty)
        reset();
    dirty = true;

#ifdef E2DEBUG
    if(is_response)
    std::cerr << thread_id << "Start of response header:in"  << std::endl;
    else
    std::cerr << thread_id << "Start of request header:in"  << std::endl;
#endif

    // the RFCs don't specify a max header line length so this should be
    // dynamic really.  Pointed out (well reminded actually) by Daniel Robbins
    char buff[32768]; // setup a buffer to hold the incomming HTTP line
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
#ifdef E2DEBUG
            std::cerr << thread_id << "header:in before getLine - timeout:" << timeout << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
            rc = sock->getLine(buff, 32768, timeout, firsttime ? honour_reloadconfig : false, NULL, &truncated);
#ifdef E2DEBUG
            std::cerr << thread_id << "firstime: header:in after getLine " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
           if (rc < 0 || truncated) {
                ispersistent = false;
#ifdef E2DEBUG
                std::cerr << thread_id << "firstime: header:in after getLine: rc: " << rc << " truncated: " << truncated  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
                dbshowheader(false);
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
#ifdef E2DEBUG
                std::cerr << thread_id << "not firstime header:in after getLine: rc: " << rc << " truncated: " << truncated << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
                dbshowheader(false);
#endif
                return false;        // do not allow non-terminated headers
            }

        }

        if (header.size() > o.max_header_lines) {
#ifdef E2DEBUG
            std::cerr << thread_id << "header:size too big =  " << header.size() << " Lines: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
	    syslog(LOG_INFO, "header:size too big: %lu, see maxheaderlines", header.size());
	    dbshowheader(false);
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
            if (!(line.length() > 11 && line.startsWith("HTTP/") && (line.after(" ").before(" ").toInteger() > 99)))
            {
                if(o.logconerror)
                    syslog(LOG_INFO, "Server did not respond with HTTP");
#ifdef E2DEBUG
                std::cerr << thread_id << "Returning from header:in Server did not respond with HTTP " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
                dbshowheader(false);
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
#ifdef E2DEBUG
            std::cerr << thread_id << "Discarding unwanted bytes at head of request (pconn closed or IE multipart POST bug)" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        }
        firsttime = false;
// End of while
    }

    if (header.size() == 0) {
#ifdef E2DEBUG
        std::cerr << thread_id << "header:size = 0 " << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return false;
    }

    header.pop_back(); // remove the final blank line of a header
#ifdef E2DEBUG
    std::cerr << thread_id << "header:size =  " << header.size() << std::endl;
    if (header.size() > 0)
    std::cerr << thread_id << "first line =  " << header[0] << std::endl;
#endif
    checkheader(allowpersistent); // sort out a few bits in the header
#ifdef E2DEBUG
    std::cerr << thread_id << "isProxyRequest is " << isProxyRequest << std::endl;
#endif
    return true;
}
