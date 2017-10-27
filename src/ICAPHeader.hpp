
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
#include "DebugManager.hpp"
// DECLARATIONS

class ICAPHeader
{
    public:
    std::deque<String> header;
    unsigned int port;
    bool is_response;
    HTTPHeader *HTTPrequest;
    HTTPHeader *HTTPresponse;
    String icap_error;
    bool service_options;
    bool service_reqmod;
    bool service_resmod;
    bool icap_reqmod_service;
    bool icap_resmod_service;

    bool req_hdr_flag;
    bool res_hdr_flag;
    bool req_body_flag;
    bool res_body_flag;
    bool opt_body_flag;
    bool null_body_flag;
    bool out_req_hdr_flag;
    bool out_res_hdr_flag;
    String out_req_header;
    String out_res_header;
    bool out_req_body_flag;
    bool out_res_body_flag;
    String out_req_body;
    String out_res_body;
    int size_req_body;
    int size_res_body;
    String ISTag;
    String username;
    String clientip;

    int req_hdr;
    int res_hdr;
    int req_body;
    int res_body;
    int opt_body;
    int null_body;


    DebugManager * myDebug;

    bool allow_204 = false;

    struct encap_rec {
        String name;
        int value;
    };

    std::deque<encap_rec> encap_recs;

    // reset header object for future use
    void reset();

    // network communication funcs

    void setTimeout(int t);
    void setHTTPhdrs(HTTPHeader &req, HTTPHeader &res);
    bool in(Socket *sock, bool allowpersistent = false );

    void setClientIP(String &ip);

    bool setEncapRecs();

    // respond with ICAP and HTTP headers and if given body
    bool respond(Socket &peersock, String rescode = "200 OK", bool echo = false);

    bool errorResponse(Socket &peersock, String &reshdr, String & resbody);

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

    ICAPHeader();
    ICAPHeader(int type);
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

    //general
    String *pproxyconnection;
    String *pencapsulated;

    //requests
    String *pauthorization;
    String *pallow;
    String *pfrom;
    String *phost;
    String *preferer;
    String *puseragent;
    String *ppreview;
    String *pxforwardedfor;

    String *pproxyauthorization;
    String *pproxyauthenticate;
    String *pcontentdisposition;
    String *pkeepalive;
    String *pupgrade;
    String *pclientip;
    String *pclientuser;
    String method;


    bool ispersistent, waspersistent;




    bool dirty;


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
