
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
    unsigned int port = 0;
    bool is_response = false;
    HTTPHeader HTTPrequest;
    HTTPHeader HTTPresponse;
    String icap_error;
    bool service_options = false;
    bool service_reqmod = false;
    bool service_resmod = false;
    bool icap_reqmod_service = false;
    bool icap_resmod_service = false;

    bool req_hdr_flag = false;
    bool res_hdr_flag = false;
    bool req_body_flag = false;
    bool res_body_flag = false;
    bool opt_body_flag = false;
    bool null_body_flag = false;
    bool out_req_hdr_flag = false;
    bool out_res_hdr_flag = false;
    String out_req_header;
    String out_res_header;
    bool out_req_body_flag = false;
    bool out_res_body_flag = false;
    String out_req_body;
    String out_res_body;
    int size_req_body = 0;
    int size_res_body = 0;
    String ISTag;
    String username;
    String clientip;


    int req_hdr = 0;
    int res_hdr = 0;
    int req_body = 0;
    int res_body = 0;
    int opt_body = 0;
    int null_body = 0;

    bool allow_204 = false;
    bool allow_206 = false;

    struct encap_rec {
        String name;
        int value = 0;
    };

    std::deque<encap_rec> encap_recs;

    struct icap_com_rec {
        String user;
        String EBG;
        int filtergroup = 0;
        int mess_no = 0;
        int log_mess_no = 0;
        String mess_string;
    };

    icap_com_rec icap_com;

    void set_icap_com (std::string &user, String EBG, int &filtergroup, int &mess_no, int &log_mess_no, std::string &mess_string);

    // reset header object for future use
    void reset();

    // network communication funcs

    void setTimeout(int t);

    bool in(Socket *sock, bool allowpersistent = false );

    void setClientIP(String &ip);

    bool setEncapRecs();

    // respond with ICAP and HTTP headers and if given body
    bool respond(Socket &peersock, String rescode = "200 OK", bool echo = false, bool encap = true);

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

    ICAPHeader()
    {
        reset();
    };

    ICAPHeader(int type)
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
        int timeout = 120000;


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




    bool dirty = true;


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
