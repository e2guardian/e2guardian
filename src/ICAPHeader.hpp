
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_ICAPHeader
#define __HPP_ICAPHeader

// INCLUDES

#include <deque>

#include "String.hpp"
#include "Socket.hpp"
#include "RegExp.hpp"
#include "ListMeta.hpp"
#include "FOptionContainer.hpp"
#include "HTTPHeader.hpp"


// DECLARATIONS

class ICAPHeader
{
    public:
    std::deque<String> header;
    unsigned int port;
    bool is_response;
    HTTPHeader *HTTPrequest;
    HTTPHeader *HTTPresponse;

    // reset header object for future use
    void reset();

    // network communication funcs

    void setTimeout(int t);
    bool in(Socket *sock, bool allowpersistent = false );

    void setClientIP(String &ip);

    // send headers out over the given socket
    bool out(Socket *peersock, Socket *sock, int sendflag, bool reconnect = false);

    // discard remainder of POST data
    // amount to discard can be passed in, or will default to contentLength()
    void discard(Socket *sock, off_t cl = -2);

    // header value and type checks

    // request type: GET, HEAD, POST etc.
    String requestType();
    int returnCode();
    // get content length - returns -1 if undetermined
    String getContentType();
    String userAgent();

    String url();
    String getUrl();

    String redirecturl();

    // header modifications

    void removeEncoding(int newlen);

    void setURL(String &url);
    // do URL decoding (%xx) on string
    // decode everything, or just numbers, letters and -
    static String decode(const String &s, bool decodeAll = false);


    // encode url
    String URLEncode();

    ICAPHeader()
        : port(0), timeout(120000),  dirty(true)
    {
        reset();
    };
    ICAPHeader(int type)
            : port(0), timeout(120000),  dirty(true), is_response(false)
    {
        reset();
        setType(type);
    };

    ~ICAPHeader()
    {
    };

    void setType(int type) {
        if (type == __HEADER_RESPONSE)
            is_response = true;
        else
            is_response = false;
    };

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

    bool ispersistent, waspersistent;

    bool dirty;

    std::string s_clientip;

    // check & fix headers from servers that don't obey standards
    void checkheader(bool allowpersistent);

    // convert %xx back to original character
    static String hexToChar(const String &n, bool all = false);
    // base64 decode an individual char
    int decode1b64(char c);
    // base64 decode a complete string
    std::string decodeb64(const String &line);

};

#endif
