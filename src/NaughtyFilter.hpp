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
    bool isTLS = false;     // used in transparent https mode
    String orig_ip;     // used in transparent https mode
    int orig_port = 0;     // used in transparent https mode

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
    bool deep_urls_checked = false;
    bool has_deep_urls = false;
    std::deque<url_rec> deep_urls;

    bool anon_log = false;
    // flags from ConnectionHandler
    bool upfailure = false;  //set when problem with upstream connection (site or proxy)
    bool waschecked = false;
    bool wasrequested = false;
    bool isexception = false;
    bool isourwebserver = false;
    bool wasclean = false;
    bool cachehit = false;
    bool isbypass = false;
    bool iscookiebypass = false;
    bool isvirusbypass = false;
    bool isscanbypass = false;
    bool isbypassallowed = false;
    bool isinfectionbypassallowed = false;
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
    String connect_site;   // the site to connect to - normally same as urldomain
    String lastmatch;
    String result;

    std::string exceptionreason; // to hold the reason for not blocking
    std::string exceptioncat;
    off_t docsize;   // to store the size of the returned document for logging
    int filtergroup;

    String tempfilename;
    String tempfilemime;
    String tempfiledis;

    // should the browser use the categories string or the displaycategories string?
    // (related to category list thresholding)
    bool usedisplaycats;
    // blocked data type - 0 = response body, 1 = request body (POST data),
    // 2 = URL parameters (search terms)
    int blocktype;
    // flag for use by ContentScanners to say whether data should be stored
    // for future inspection.  storage only implemented for POST data.
    bool store;

    int message_no;
    int log_message_no;

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
    void reset();

    void setURL(bool set_ismitm = false);
    void setURL(String &sni);

    void checkme(const char *rawbody, off_t rawbodylen, const String *url, const String *domain,
        FOptionContainer* &foc, unsigned int phraselist, int limit, bool searchterms = false);

    // highest positive (or lowest negative) weighting out of
    // both phrase filtering passes (smart/raw)
    int naughtiness;
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
