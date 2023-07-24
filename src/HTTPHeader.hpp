
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_HTTPHeader
#define __HPP_HTTPHeader

// DEFINES

#define __E2HEADER_SENDALL 0
#define __E2HEADER_SENDFIRSTLINE 1
#define __E2HEADER_SENDREST 2

#define  __HEADER_REQUEST      1
#define  __HEADER_RESPONSE   2

// INCLUDES

#include <deque>

#include "String.hpp"
//#include "DataBuffer.hpp"
#include "Socket.hpp"
#include "RegExp.hpp"
#include "ListMeta.hpp"
#include "FOptionContainer.hpp"

// DECLARATIONS

class HTTPHeader
{
    public:
    std::deque<String> header;
    //DataBuffer postdata;
    unsigned int port;
    bool is_response = false;
    bool icap;
    String redirect;
    String useragent;
    String contenttype;
    String contentencoding;
    String transferencoding;

    // reset header object for future use
    void reset();

    // network communication funcs

    void setTimeout(int t);
    bool in(Socket *sock, bool allowpersistent = false );
    bool in_handle_100(Socket *sock, bool allowpersistent = false, bool expect_100 = false );

    void setClientIP(String &ip);
    String getClientIP();

    String stringHeader();  // output header as a String (used by ICAP)

    // send headers out over the given socket
    // "reconnect" flag gives permission to reconnect to the socket on write error
    // - this allows us to re-open the proxy connection on pconns if squid's end has
    // timed out but the client's end hasn't. not much use with NTLM, since squid
    // will throw a 407 and restart negotiation, but works well with basic & others.
    //void out(Socket *peersock, Socket *sock, int sendflag, bool reconnect = false) throw(std::exception);
    bool out(Socket *peersock, Socket *sock, int sendflag, bool reconnect = false);

    // discard remainder of POST data
    // amount to discard can be passed in, or will default to contentLength()
    void discard(Socket *sock, off_t cl = -2);

    // header value and type checks

    // request type: GET, HEAD, POST etc.
    String requestType();
    String requesttype;
    int returnCode();
    int returncode;

    // get content length - returns -1 if undetermined
    off_t contentLength();
    String getContentType();
    bool OKtoFilterMime(FOptionContainer* &foc);
    String getMIMEBoundary();
    // check received content type against given content type
    //bool isContentType(const String &t,int filtergroup);
    bool isContentType(const String &t,FOptionContainer* &foc);
    // check HTTP message code to see if it's an auth required message
    bool authRequired();
    // Content-Disposition
    String disposition();
    String userAgent();
    String findHeader(String &label);
    // grab contents of X-Forwarded-For
    std::string getXForwardedForIP();
    // check HTTP message code to see if it's a redirect
    bool isRedirection();
    // see if content-type is something other than "identity"
    bool isCompressed();
    bool addHeader(String & xheader);
    //bool isHeaderAdded(int filtergroup);
    bool isHeaderAdded(FOptionContainer* &foc);
    bool addheaderchecked;
    bool isheaderadded;
    String *plogheadervalue;
    String *pheaderident;
    String *ptransfercoding;
    String *ptransferencoding;
    std::string getAuthHeader();
    // see if search usl and set searchwords
    bool isSearch(FOptionContainer* &foc);
    String searchwords();
    String searchterms();
    bool searchchecked;
    bool chunked;
    bool expects_100 = false;
    String contentEncoding();
    String transferEncoding();
    // grab the contents of Proxy-Authorization header
    // returns base64-decoding of the chunk of data after the auth type string
    std::string getAuthData();
    // grab raw contents of Proxy-Authorization header, without b64 decode
    std::string getRawAuthData();
    // Debug show header
    void dbshowheader(String *url, const char *clientip);
    void dbshowheader(bool outgoing);
    // check whether a connection is persistent
    bool isPersistent()
    {
        return ispersistent;
    };
    bool wasPersistent()
    {
        return waspersistent;
    };

    // set POST data for outgoing requests.
    // assumes that existing POST data has already been discarded
    // or retrieved elsewhere, and sends this data instead when ::out
    // is called.
    void setPostData(const char *data, size_t len);

    void setDirect();


    // detailed value/type checks

    bool malformedURL(const String &url);
    String getAuthType();
    String getUrl(bool withport = false, bool isssl = false);
    String getLogUrl(bool withport = false, bool isssl = false);
    String url();

    String redirecturl();

    // header modifications

    void addXForwardedFor(const std::string &clientip);
    // strip content-encoding, and simultaneously set content-length to newlen
    void removeEncoding(int newlen);
    void setContentLength(int newlen);

    //bool DenySSL(FOptionContainer* &foc);
    // make a connection persistent - or not
    void makePersistent(bool persist = true);
    // make the request look as if its coming from the origin server
    void makeTransparent(bool incoming);
    // modifies the URL in all relevant header lines after a regexp search and replace
    // setURL Code originally from from Ton Gorter 2004
    void setURL(String &url);

    // modifies connect site only - leaves other headers alone
    void setConnect(String &con_site);
    // do URL decoding (%xx) on string
    // decode everything, or just numbers, letters and -
    static String decode(const String &s, bool decodeAll = false);

    // Bypass URL & Cookie funcs

    bool isBypassCookie(String url, const char *magic, const char *clientip, const char *user);
    //void chopBypass(String url, bool infectionbypass);
    void chopBypass(String url,std::string bp_type);
    //void chopScanBypass(String url);
    // add cookie to outgoing headers with given name & value
    void setCookie(const char *cookie, const char *domain, const char *value);
    bool isProxyRequest;

    // encode url
    String URLEncode();

    // grab referer url from headers
    String getReferer();

    HTTPHeader()
    //    : port(0), timeout(120000), contentlength(0), postdata(NULL), dirty(true), is_response(false)
        : port(0), timeout(120000), contentlength(0), postdata(NULL), dirty(true)
    {
        reset();
    };
    HTTPHeader(int type)
    //        : port(0), timeout(120000), contentlength(0), postdata(NULL), dirty(true), is_response(false)
    : port(0), timeout(120000), contentlength(0), postdata(NULL), dirty(true)
    {
        reset();
        setType(type);
    };

    ~HTTPHeader()
    {
        delete postdata;
    };

    void setType(int type) {
        if (type == __HEADER_RESPONSE)
            is_response = true;
        else
            is_response = false;
    };

    // generate bypass hashed url
    String hashedURL(String *url,  std::string *clientip,
                     bool infectionbypass, std::string *user, FOptionContainer &fdl, bool fakecgi = false);
    // generate bypass hashed cookie
    String hashedCookie(String *url, const char *magic, std::string *clientip, int bypasstimestamp, std::string user);

    // base64 decode a complete string
    std::string decodeb64(const String &line);

private:
        // timeout for socket operations
        int timeout;


    // header index pointers
    String *phost;
    String *pport;
    String *pcontentlength;
    String *pcontenttype;
    String *pproxyauthorization;
    String *pauthorization;
    String *pproxyauthenticate;
    String *pcontentdisposition;
    String *puseragent;
    String *pxforwardedfor;
    String *pcontentencoding;
    String *pproxyconnection;
    String *pkeepalive;

    // cached result of getUrl()
    std::string cachedurl;
    // used to record if it is a header within a MITM
    bool mitm = false;
    // is direct rather than via proxy
    bool isdirect = false;

    String searchwds;
    //std::string searchwds;
    //std::string searchtms;
    String searchtms;
    bool issearch;

    // cached result of contentLength()
    off_t contentlength;
    bool clcached;

    // replacement POST data for sending during ::out
    char *postdata;
    size_t postdata_len;

    bool ispersistent, waspersistent;

    bool dirty;

    std::string s_clientip;

    // check & fix headers from servers that don't obey standards
    void checkheader(bool allowpersistent);

    // convert %xx back to original character
    static String hexToChar(const String &n, bool all = false);
    // base64 decode an individual char
    int decode1b64(char c);

    // modify supplied accept-encoding header, adding "identity" and stripping unsupported compression types
    String modifyEncodings(String e);

    // Generic search & replace code, called by urlRegExp and headerRegExp
    // urlRegExp Code originally from from Ton Gorter 2004
    bool regExp(String &line, std::deque<RegExp> &regexp_list, std::deque<String> &replacement_list);

    // grab cookies from headers
    String getCookie(const char *cookie);

};

#endif
