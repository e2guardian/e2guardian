// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_NAUGHTYFILTER
#define __HPP_NAUGHTYFILTER

// INCLUDES

// not sure if these are needed - but are in protexofe - PIP
//#include "String.hpp"
//#include "OptionContainer.hpp"
//#include "DataBuffer.hpp"

#include "FOptionContainer.hpp"
// DECLARATIONS

class NaughtyFilter
{
    public:
    // should the content be blocked?
    bool isItNaughty;
    // should the content bypass any further filtering?
    bool isException;
    // is the url/site in Greylist - forces content check
    bool isGrey;
    // is the url/site in SSLGreylist
    bool isSSLGrey;
    // is the url a search request
    bool isSearch;
    // should the browser use the categories string or the displaycategories string?
    // (related to category list thresholding)
    bool usedisplaycats;
    // blocked data type - 0 = response body, 1 = request body (POST data),
    // 2 = URL parameters (search terms)
    int blocktype;
    // flag for use by ContentScanners to say whether data should be stored
    // for future inspection.  storage only implemented for POST data.
    bool store;

    // not sure if these are needed - but are in protexofe - PIP
    //int filtergroup;
    // Used in Protex format logs??
    int message_no;

    // the reason for banning, what to say about it in the logs, and the
    // categories under which banning has taken place
    std::string whatIsNaughty;
    std::string whatIsNaughtyLog;
    std::string whatIsNaughtyCategories;
    std::string whatIsNaughtyDisplayCategories;

    NaughtyFilter();
    void reset();
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

#endif
