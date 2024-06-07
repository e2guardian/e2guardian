// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_NAUGHTYFILTER
#define __HPP_NAUGHTYFILTER

// INCLUDES

//#include "String.hpp"
//#include "OptionContainer.hpp"
//#include "DataBuffer.hpp"
#include "HTTPHeader.hpp"
//#include "FOptionContainer.hpp"
#include "UrlRec.hpp"
#include "Auth.hpp"

class FOptionContainer;

// DECLARATIONS        bool isListCheck = false;

class NaughtyFilter
{
    public:
    // should the content be blocked?
    bool isItNaughty = false;
    // should the content bypass any further filtering?
    bool isException = false;
    // is the url/site in Greylist - forces content check
    bool isGrey = false;
    // is the url/site in SSLGreylist
    bool isSSLGrey = false;
    // is the url a search request
    bool isSearch = false;
    // is the url to be blocked
    bool isBlocked = false;
    bool hasSNI = false;     // used in transparent https mode
    bool hasECH = false;     // used in transparent https mode
    bool isTLS = false;     // used in transparent https mode
    String orig_ip;     // used in transparent mode
    int orig_port = 0;     // used in transparent mode
    bool got_orig_ip = false;     // used in transparent mode
    // bad certificat
    bool badcert = false;
    int listen_port = 0;    // listening port
    struct auth_rec *authrec = nullptr;

    // return true or false?
    bool isReturn = false;

    bool reverse_checked = false;

    bool hasEmbededURL = false;
    std::deque<String> embededURLs;
    std::deque<url_rec> reversedURLs;

    HTTPHeader* request_header;
    HTTPHeader* response_header;

    bool isIPHostnameStrip(String url);

    RegExp ch_isiphost;
    RegResult Rch_isiphost;

    bool gomitm = false;
    bool nomitm = false;
    bool automitm = false;
    bool alert = false;
    bool deep_urls_checked = false;
    bool has_deep_urls = false;
    std::deque<url_rec> deep_urls;

    bool anon_user = false;
    bool anon_url = false;
    // flags from ConnectionHandler
    bool upfailure = false;  //set when problem with upstream connection (site or proxy)
    bool waschecked = false;
    bool wasrequested = false;
    bool isexception = false;
    bool issemiexception = false;
    bool isourwebserver = false;
    bool wasclean = false;
    bool cachehit = false;
    bool isbypass = false;
    bool iscookiebypass = false;
    bool isvirusbypass = false;
    bool isscanbypass = false;
    bool isbypassallowed = false;
    bool isinfectionbypassallowed = false;
    bool isscanbypassallowed = false;
    bool istoobigbypassallowed = false;
    bool ispostblock = false;
    bool pausedtoobig = false;
    bool wasinfected = false;
    bool wasscanned = false;
    bool contentmodified = false;
    bool urlmodified = false;
    bool headermodified = false;
    bool headeradded = false;
    bool isconnect = false;
    bool ishead = false;
    bool isiphost = false;
    bool scanerror = false;
    bool ismitmcandidate = false;
    bool is_ssl = false;
    bool is_ip = false;
    bool ismitm = false;
    bool isdone = false;
    bool nolog = false;
    bool nocheckcert = false;
    bool logcategory = false;
    bool noviruscheck = true;
    bool urlredirect = false;
    bool isdirect = false;   // go direct if true via proxy if false
    bool tunnel_rest = false;
    bool tunnel_2way = false;
    bool is_text = false;
    bool issiteonly = false;
    int auth_result = 0;
    String search_words;
    String search_terms;
    struct timeval thestart;

    // 0=none,1=first line,2=all
    int headersent = 0;

    int bypasstimestamp = 0;

    std::string mimetype;

    String url;     // the normalised url
    String baseurl;   // url with 'http[s]://'  removed
    String logurl;      // url with called protocol
    String urld;          // decoded url
    String urldomain;   // the domain or site part of the url
    String urldomainport;   // the domain or site part of the url with port number
    String connect_site;   // the site to connect to - normally same as urldomain
    String user;    // result of auth plug-in id - may be network log-in name or client IP or port
    String realuser; // real or authed user name
    String lastmatch;
    String result;

    String get_lastmatch();
    String get_logUrl();
    String main_category();

    std::string exceptionreason; // to hold the reason for not blocking
    std::string exceptioncat;
    off_t docsize;   // to store the size of the returned document for logging
    int filtergroup;

    String tempfilename;
    String tempfilemime;
    String tempfiledis;

    // should the browser use the categories string or the displaycategories string?
    // (related to category list thresholding)
    bool usedisplaycats = false;
    // blocked data type - 0 = response body, 1 = request body (POST data),
    // 2 = URL parameters (search terms)
    int blocktype = 0;
    // flag for use by ContentScanners to say whether data should be stored
    // for future inspection.  storage only implemented for POST data.
    bool store = false;

    int message_no = 0;
    int log_message_no = 0;

    // the reason for banning, what to say about it in the logs, and the
    // categories under which banning has taken place
    std::string whatIsNaughty;
    std::string whatIsNaughtyLog;
    std::string whatIsNaughtyCategories;
    std::string whatIsNaughtyDisplayCategories;
    std::string clienthost;
    std::string clientip;

    NaughtyFilter();
    NaughtyFilter(HTTPHeader &request, HTTPHeader &response);
    NaughtyFilter(HTTPHeader &request, HTTPHeader &response, auth_rec &authrecin);
    void reset();

    void setURL(bool set_ismitm = false);
    void setURL(String &sni);

    void checkme(const char *rawbody, off_t rawbodylen, const String *url, const String *domain,
        FOptionContainer* &foc, unsigned int phraselist, int limit, bool searchterms = false);

    String getFlags();

    // highest positive (or lowest negative) weighting out of
    // both phrase filtering passes (smart/raw)
    int naughtiness = 0;
    String lastcategory;

    private:
    // check the banned, weighted & exception lists
    // pass in both URL & domain to activate embedded URL checking
    // (this is made optional in this manner because it's pointless
    // trying to look for links etc. in "smart" filtering mode, i.e.
    // after HTML has been removed, and in search terms.)
    void checkphrase(char *file, off_t filelen, const String *url, const String *domain,
        FOptionContainer* &foc, unsigned int phraselist, int limit, bool searchterms);

};

#define __HPP_NAUGHTYFILTER
#endif
