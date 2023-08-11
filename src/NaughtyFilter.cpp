// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "String.hpp"
#include "OptionContainer.hpp"
#include "NaughtyFilter.hpp"
#include "RegExp.hpp"
#include "ListContainer.hpp"
#include "Logger.hpp"

#include <cstring>
#include <algorithm>
#include <netdb.h>


// GLOBALS

extern OptionContainer o;
extern thread_local std::string thread_id;
extern thread_local std::string request_id;

#ifdef HAVE_PCRE
extern RegExp absurl_re, relurl_re;
#endif

// DECLARATIONS

// category list entry class - stores category index & weight of all phrases
// found so far that fall under this category. also includes a less-than
// operator so that the STL sort algorithm can be applied to lists of these.
class listent
{
    public:
    listent()
        : weight(0), string(""){};
    listent(const int &w, String &s)
    {
        weight = w;
        string = s;
    };
    int weight;
    String string;
    int operator<(const listent &a) const
    {
        // sort in descending order of score
        return weight > a.weight ? 1 : 0;
    };
};

// IMPLEMENTATION

// constructor - set up defaults
NaughtyFilter::NaughtyFilter()
{
    ch_isiphost.comp(",*[a-z|A-Z].*");
}
NaughtyFilter::NaughtyFilter(HTTPHeader &request, HTTPHeader &response)
{
    request_header = &request;
    response_header = &response;
    ch_isiphost.comp(",*[a-z|A-Z].*");
    reset();
}

NaughtyFilter::NaughtyFilter(HTTPHeader &request, HTTPHeader &response, auth_rec &authrecin)
{
    request_header = &request;
    response_header = &response;
    authrec = &authrecin;
    ch_isiphost.comp(",*[a-z|A-Z].*");
    reset();
}
void NaughtyFilter::setURL(bool set_ismitm) {
    // do all of this normalisation etc just the once at the start.
    url = request_header->getUrl(false, false);
    baseurl = url;
    baseurl.removeWhiteSpace();
    baseurl.toLower();
    baseurl.removePTP();
    logurl = request_header->getLogUrl(false, set_ismitm);
    urld = request_header->decode(url);
    urldomain = url.getHostname();
    urldomain.toLower();
    String temp;
    temp = request_header->getUrl(true,false);  // get url with port
    urldomainport = temp.getHostname();
    urldomainport.toLower();

    connect_site = urldomain;
    isiphost = isIPHostnameStrip(urldomain);
    is_ssl = request_header->requestType().startsWith("CONNECT");
    ishead = request_header->requestType().startsWith("HEAD");
    isconnect = is_ssl;
    ismitm = set_ismitm;
    if (baseurl == urldomain)
        issiteonly = true;
    docsize = 0;
}

void NaughtyFilter::setURL(String &sni) {
    // do all of this normalisation etc just the once at the start.
    url = sni;
    baseurl = url;
    baseurl.removeWhiteSpace();
    baseurl.toLower();
    baseurl.removePTP();
    logurl = url;
    urld = request_header->decode(url);
    urldomain = url.getHostname();
    urldomain.toLower();
    connect_site = urldomain;
    isiphost = isIPHostnameStrip(urldomain);
    if (baseurl == urldomain)
        issiteonly = true;
    docsize = 0;
}

void NaughtyFilter::reset()
{
    anon_user = o.log.anonymise_logs;
    anon_url = false;
    logurl = "";
    isItNaughty = false;
    isException = false;
    whatIsNaughty = "";
    whatIsNaughtyLog = "";
    whatIsNaughtyCategories = "";
    tempfilename = "";
    tempfilemime= "";
    tempfiledis= "";
    usedisplaycats = false;
    blocktype = 0;
    store = false;
    naughtiness = 0;
    isGrey = false;
    isSSLGrey = false;
    isSearch = false;
    message_no = 0;
    is_text = false;
    filtergroup = 0;
    deep_urls_checked = false;
    has_deep_urls = false;
    issiteonly = false;

    gomitm = false;
    nomitm = false;
    automitm = false;
    // resets from CH
    waschecked = false; // flags
    wasrequested = false;
    isexception = false;
    issemiexception = false;
    isourwebserver = false;
    wasclean = false;
    isbypass = false;
    iscookiebypass = false;
    isvirusbypass = false;
    isbypassallowed = false;
    isinfectionbypassallowed = false;
    bypasstimestamp = 0;
    isscanbypass = false;
    ispostblock = false;
    pausedtoobig = false;
    wasinfected = false;
    wasscanned = false;
    contentmodified = false;
    urlmodified = false;
    headermodified = false;
    headeradded = false;
    nocheckcert = false;
    noviruscheck = true;
    headersent = 0;
    message_no = 0;
    log_message_no = 0;
    urlredirect = false;
    logcategory = false;
    upfailure = false;
    isdirect = o.net.no_proxy;  // always set if no proxy defined
    //            authed = false;
    //            isbanneduser = false;
    mimetype = "-";
    docsize = 0; // to store the size of the returned document for logging
    orig_ip = "";
    orig_port = 0;
    got_orig_ip = false;
    destIPs_dq.clear();
    destIP.clear();

}

// check the given document body for banned, weighted, and exception phrases (and PICS, and regexes, &c.)
// also used for scanning search terms, which causes various features - PICS, META/TITLE extraction, etc. - to be disabled
void NaughtyFilter::checkme(const char *rawbody, off_t rawbodylen, const String *url,
    const String *domain, FOptionContainer* &foc, unsigned int phraselist, int limit, bool searchterms)
{
    if (searchterms) {
        DEBUG_content("Content flagged as search terms - disabling hex decoding, META/TITLE extraction & HTML removal");
    }


    if (foc->weighted_phrase_mode == 0) {
        DEBUG_content("Weighted phrase mode 0 - not going any further.");
        return;
    }

    // hex-decoded data (not case converted)
    off_t hexdecodedlen = rawbodylen;
    const char *hexdecoded = rawbody;

    unsigned char c;

    // Hex decode content if desired
    // Do this now, as it's not especially case-sensitive,
    // and the case alteration should modify case post-decoding
    // Search terms are already hex decoded, as they need to be to strip URL decoding
    if (!searchterms && o.naughty.hex_decode_content) { // Mod suggested by AFN Tue 8th April 2003
        DEBUG_content("Hex decoding is enabled");
        char *hexdecoded_buf = new char[rawbodylen + 128 + 1];
        memset(hexdecoded_buf, 0, rawbodylen + 128 + 1);
        unsigned char c1;
        unsigned char c2;
        unsigned char c3;
        char hexval[5] = "0x"; // Initializes a "hexadecimal string"
        hexval[4] = '\0';
        char *ptr; // pointer required by strtol

        // make a copy of the escaped document char by char
        off_t i = 0;
        off_t j = 0;
        while (i < rawbodylen - 3) { // we lose 3 bytes but what the hell..
            c1 = rawbody[i];
            c2 = rawbody[i + 1];
            c3 = rawbody[i + 2];
            if (c1 == '%' && (((c2 >= '0') && (c2 <= '9')) || ((c2 >= 'a') && (c2 <= 'f')) || ((c2 >= 'A') && (c2 <= 'F')))
                && (((c3 >= '0') && (c3 <= '9')) || ((c3 >= 'a') && (c3 <= 'f')) || ((c3 >= 'A') && (c3 <= 'F')))) {
                hexval[2] = c2;
                hexval[3] = c3;
                c = (unsigned char)strtol(hexval, &ptr, 0);
                i += 3;
            } else {
                c = c1;
                i++;
            }
            hexdecoded_buf[j] = c;
            j++;
        }
        // copy any remaining bytes
        while (i < rawbodylen) {
            hexdecoded_buf[j++] = rawbody[i++];
        }
        hexdecoded_buf[j] = '\0';
        hexdecodedlen = j;
        hexdecoded = hexdecoded_buf;
    }

    // scan twice, with & without case conversion (if desired) - aids support for exotic char encodings
    // TODO: move META/title sentinel location outside this loop, as they are not case sensitive operations
    bool preserve_case = (o.naughty.preserve_case != 0);
    bool do_raw = false;
    bool do_nohtml = false;

    if (o.naughty.preserve_case == 2) {
        // scanning twice *is* desired
        // first time round the loop, don't preserve case (non-exotic encodings)
        DEBUG_content("Filtering with/without case preservation is enabled");
        preserve_case = false;
    }

    // Store for the lowercase (maybe) data
    // The extra 128 is used for various speed tricks to
    // squeeze as much speed as possible.
    char *bodylc = new char[hexdecodedlen + 128 + 1];
    memset(bodylc, 0, hexdecodedlen + 128 + 1);

    // Store for the tag-stripped data
    // Don't bother tag stripping search terms
    char *bodynohtml = NULL;
    if (!searchterms && (o.naughty.phrase_filter_mode == 1 || o.naughty.phrase_filter_mode == 2)) {
        do_nohtml = true;
        bodynohtml = new char[hexdecodedlen + 128 + 1];
        memset(bodynohtml, 0, hexdecodedlen + 128 + 1);
    }

    if ((o.naughty.phrase_filter_mode == 0 || o.naughty.phrase_filter_mode == 2 || o.naughty.phrase_filter_mode == 3))
        do_raw = true;

    for (int loop = 0; loop < (o.naughty.preserve_case == 2 ? 2 : 1); loop++) {
        DEBUG_content("Preserve case: ", preserve_case );

        off_t i, j;
        if (searchterms || do_raw)
            DEBUG_content("Raw content needed");

        // use the one that's been hex decoded, but not stripped
        // make a copy of the document lowercase char by char
        if (preserve_case) {
            if (do_nohtml || o.naughty.phrase_filter_mode == 3) {
                for (i = 0; i < hexdecodedlen; i++) {
                    c = hexdecoded[i];
                    //				if (c == 13 || c == 9 || c == 10) {
                    if (c < '/' || c == ':' || c == ';' || c == '=' || c == '?' || c == '@' || (c > 90 && c < 97)) {
                        c = 32; // convert all whitespace and most punctuation marks to a space
                    }
                    bodylc[i] = c;
                }
            } else { // not being html striped so can remove < > now
                for (i = 0; i < hexdecodedlen; i++) {
                    c = hexdecoded[i];
                    //				if (c == 13 || c == 9 || c == 10) {
                    if (c < '/' || (c > '9' && c < 'A') || (c > 'Z' && c < 'a')) {
                        c = 32; // convert all whitespace and most punctuation marks to a space
                    }
                    bodylc[i] = c;
                }
            }
        } else {
            DEBUG_content("Not preserving case of raw content");
            if (do_nohtml || o.naughty.phrase_filter_mode == 3) {
                for (i = 0; i < hexdecodedlen; i++) {
                    c = hexdecoded[i];
                    if (c >= 'A' && c <= 'Z') {
                        c = 'a' + c - 'A';
                    } else if (c >= 192 && c <= 221) { // for accented chars
                        c += 32; // 224 + c - 192
                    } else {
                        //if (c == 13 || c == 9 || c == 10) {
                        if (c < '/' || c == ':' || c == ';' || c == '=' || c == '?' || c == '@' || (c > 90 && c < 97)) {
                            c = 32; // convert all whitespace and most punctuation marks to a space
                        }
                    }
                    bodylc[i] = c;
                }
            } else { // not being html striped so can remove < > now
                for (i = 0; i < hexdecodedlen; i++) {
                    c = hexdecoded[i];
                    if (c >= 'A' && c <= 'Z') {
                        c = 'a' + c - 'A';
                    } else if (c >= 192 && c <= 221) { // for accented chars
                        c += 32; // 224 + c - 192
                    } else {
                        //if (c == 13 || c == 9 || c == 10) {
                        if (c < '/' || (c > '9' && c < 'A') || (c > 'Z' && c < 'a')) {
                            c = 32; // convert all whitespace and most punctuation marks to a space
                        }
                    }
                    bodylc[i] = c;
                }
            }
        }

        // filter meta tags & title only
        // based on idea from Nicolas Peyrussie
        if (!searchterms && (o.naughty.phrase_filter_mode == 3)) {
            DEBUG_content("Filtering META/title");
            bool addit = false; // flag if we should copy this char to filtered version
            bool needcheck = false; // flag if we actually find anything worth filtering
            off_t bodymetalen;

            // find </head> or <body> as end of search range
            char *endhead = strstr(bodylc, "</head");
            if (endhead != NULL)
                DEBUG_content("Found '</head', limiting search range");
            if (endhead == NULL) {
                endhead = strstr(bodylc, "<body");
                if (endhead != NULL)
                    DEBUG_content("Found '<body', limiting search range");
            }

            // if case preserved, also look for uppercase versions
            if (preserve_case and (endhead == NULL)) {
                endhead = strstr(bodylc, "</HEAD");
                if (endhead != NULL)
                    DEBUG_content("Found '</HEAD', limiting search range");
                if (endhead == NULL) {
                    endhead = strstr(bodylc, "<BODY");
                    if (endhead != NULL)
                        DEBUG_content("Found '<BODY', limiting search range");
                }
            }

            if (endhead == NULL)
                endhead = bodylc + hexdecodedlen;

            char *bodymeta = new char[(endhead - bodylc) + 128 + 1];
            memset(bodymeta, 0, (endhead - bodylc) + 128 + 1);

            // initialisation for removal of duplicate non-alphanumeric characters
            j = 1;
            bodymeta[0] = 32;

            for (i = 0; i < (endhead - bodylc) - 7; i++) {
                c = bodylc[i];
                // are we at the start of a tag?
                if ((!addit) && (c == '<')) {
                    if ((strncmp(bodylc + i + 1, "meta", 4) == 0) or (preserve_case and (strncmp(bodylc + i + 1, "META", 4) == 0))) {
                        DEBUG_content("Found META");
                        // start adding data to the check buffer
                        addit = true;
                        needcheck = true;
                        // skip 'meta '
                        i += 6;
                        c = bodylc[i];
                    }
                    // are we at the start of a title tag?
                    else if ((strncmp(bodylc + i + 1, "title", 5) == 0) or (preserve_case and (strncmp(bodylc + i + 1, "TITLE", 5) == 0))) {
                        DEBUG_content("Found TITLE");
                        // start adding data to the check buffer
                        addit = true;
                        needcheck = true;
                        // skip 'title>'
                        i += 7;
                        c = bodylc[i];
                    }
                }
                // meta tags end at a >
                // title tags end at the next < (opening of </title>)
                if (addit && ((c == '>') || (c == '<'))) {
                    // stop ading data
                    addit = false;
                    // add a space before the next word in the check buffer
                    bodymeta[j++] = 32;
                }

                if (addit) {
                    // if we're in "record" mode (i.e. inside a title/metatag), strip certain characters out
                    // of the data (to sanitise metatags & aid filtering of titles)
                    //if (c == ',' || c == '=' || c == '"' || c == '\''
                    //    || c == '(' || c == ')' || c == '.') {
                    //    // replace with a space
                    //    c = 32;
                    //}
                    // don't bother duplicating spaces
                    if ((c != 32) || (c == 32 && (bodymeta[j - 1] != 32))) {
                        bodymeta[j++] = c; // copy it to the filtered copy
                    }
                }
            }
            if (needcheck) {
                bodymeta[j++] = '\0';
                DEBUG_content(bodymeta);
                bodymetalen = j;
                checkphrase(bodymeta, bodymetalen, NULL, NULL, foc, phraselist, limit, searchterms);
            }
            else
                DEBUG_content("Nothing to filter");

            delete[] bodymeta;
            // surely the intention is to search *only* meta/title, so always exit
            delete[] bodylc;
            delete[] bodynohtml;
            if (hexdecoded != rawbody)
                delete[] hexdecoded;
            return;
        }

        if (do_nohtml) {
            // if we fell through to here, use the one that's been hex decoded AND stripped
            // Strip HTML
            DEBUG_content("\"Smart\" filtering is enabled");
            // we need this extra byte *
            bool inhtml = false; // to flag if our pointer is within a html <>
            bool addit; // flag if we should copy this char to filtered version
            j = 1;
            bodynohtml[0] = 32; // * for this
            for (off_t i = 0; i < hexdecodedlen; i++) {
                addit = true;
                c = bodylc[i];
                if (c == '<') {
                    inhtml = true; // flag we are inside a html <>
                }
                if (c == '>') { // flag we have just left a html <>
                    inhtml = false;
                    c = 32;
                }
                if (inhtml) {
                    addit = false;
                }
                if (c == 32) {
                    if (bodynohtml[j - 1] == 32) { // * and this
                        addit = false;
                    }
                }
                if (addit) { // if it passed the filters
                    bodynohtml[j++] = c; // copy it to the filtered copy
                }
            }
            DEBUG_content("Checking smart content");
            checkphrase(bodynohtml, j - 1, NULL, NULL, foc, phraselist, limit, searchterms);
            if (isItNaughty || isException) {
                delete[] bodylc;
                delete[] bodynohtml;
                if (hexdecoded != rawbody)
                    delete[] hexdecoded;
                return; // Well there is no point in continuing is there?
            }
        }

        if (!do_raw) {
            delete[] bodylc;
            delete[] bodynohtml;
            if (hexdecoded != rawbody)
                delete[] hexdecoded;
            return; // only doing nohtml mode filtering
        } else {
            DEBUG_content("Checking raw content");

            if (do_nohtml) { // already removed if not!
                // replace html tag start and finish with space so that Start and finish words are detected
                for (i = 0; i < hexdecodedlen; i++) {
                    c = bodylc[i];
                    if (c == '>' || c == '<')
                        bodylc[i] = 32;
                }
            }

            // check unstripped content
            checkphrase(bodylc, hexdecodedlen, url, domain, foc, phraselist, limit, searchterms);
            if (isItNaughty || isException) {
                delete[] bodylc;
                delete[] bodynohtml;
                if (hexdecoded != rawbody)
                    delete[] hexdecoded;
                return; // Well there is no point in continuing is there?
            }
        }

        // second time round the case loop (if there is a second time),
        // do preserve case (exotic encodings)
        preserve_case = true;
    }
    delete[] bodylc;
    delete[] bodynohtml;
    if (hexdecoded != rawbody)
        delete[] hexdecoded;
}

// check the phrase lists
void NaughtyFilter::checkphrase(char *file, off_t filelen, const String *url, const String *domain,
    FOptionContainer* &foc, unsigned int phraselist, int limit, bool searchterms)
{
    int weighting = 0;
    unsigned int cat;
    RegResult Rre;
    std::string weightedphrase;
    String lastcategory;

    // checkme: translate this?
    String currcat("Embedded URLs");

    // found categories list & reusable iterators
    std::map<int, listent> listcategories;

// check for embedded references to banned sites/URLs.
// have regexes that check for URLs in pages (look for attributes (src, href, javascript location)
// or look for protocol strings (in which case, incl. ftp)?) and extract them.
// then check the extracted list against the banned site/URL lists.
// ADs category lists do not want to add to the possibility of a site being banned.
// Exception lists are not checked.
// Do not do full-blown category retrieval/duplicate checking; simply add the
// "Embedded URLs" category.
// Put a warning next to the option in the config file that this will take lots of CPU.
// Support phrase mode 1/2 distinction (duplicate sites/URLs).
// Have weight configurable per filter group, not globally or with a list directive -
//   a weight of 0 will disable the option, effectively making this functionality per-FG itself.

// todo: if checkphrase is passed the domain & existing URL, it can create full URLs from relative ones.
// if a src/href URL starts with a /, append it to the domain; otherwise, append it to the existing URL.
// chop off anything after a ?, run through realPath, then put through the URL lists.

#ifdef HAVE_PCRE
    // if weighted phrases are enabled, and we have been passed a URL and domain, and embedded URL checking is enabled...
    // then check for embedded URLs!
#ifdef LEAVE_OUT_FOR_NOW
    // TODO - THIS SECTION DISABLED IN V5 - REVIISIT LATER IF NEEDED
    if (url != NULL && foc->embedded_url_weight > 0) {
        std::map<int, listent>::iterator ourcat;
        bool catinited = false;
        std::map<String, unsigned int> found;
        std::map<String, unsigned int>::iterator founditem;

        String u;
        char *j;

        // check for absolute URLs
        if (absurl_re.match(file, Rre)) {
            // each match generates 2 results (because of the brackets in the regex), 
            // we're only interested in the first
            DEBUG_content("Found ", Rre.numberOfMatches() / 2, " absolute URLs:");
            for (int i = 0; i < Rre.numberOfMatches(); i += 2) {
                // chop off quotes
                u = Rre.result(i);
                u = u.subString(1, u.length() - 2);
                DEBUG_content(u);

                if ((((j = foc->inBannedSiteList(u, false, false, false, lastcategory)) != NULL) &&
                    !(lastcategory.contains("ADs")))
                    || (((j = foc->inBannedURLList(u, false, false,false, lastcategory )) != NULL) &&
                          !(lastcategory.contains("ADs")))) {
                    // duplicate checking
                    // checkme: this should really be being done *before* we search the lists.
                    // but because inBanned* methods do some cleaning up of their own, we don't know the form to check against.
                    // we actually want these cleanups do be done before passing to inBanned*/inException* - this would
                    // speed up ConnectionHandler a bit too.
                    founditem = found.find(j);
                    if ((foc->weighted_phrase_mode == 2) && (founditem != found.end())) {
                        founditem->second++;
                    } else {
                        // add the site to the found phrases list
                        found[j] = 1;
                        if (weightedphrase.length() == 0)
                            weightedphrase = "[";
                        else
                            weightedphrase += " ";
                        weightedphrase += j;
                        if (!catinited) {
                            listcategories[-1] = listent(foc->embedded_url_weight, currcat);
                            ourcat = listcategories.find(-1);
                            catinited = true;
                        } else
                            ourcat->second.weight += foc->embedded_url_weight;
                    }
                }
            }
        }

        found.clear();

        // check for relative URLs
        if (relurl_re.match(file,Rre)) {
            // we don't want any parameters on the end of the current URL, since we append to it directly
            // when forming absolute URLs from relative ones. we do want a / on the end, too.
            String currurl(*url);
            if (currurl.contains("?"))
                currurl = currurl.before("?");
            if (currurl[currurl.length() - 1] != '/')
                currurl += "/";

            // each match generates 2 results (because of the brackets in the regex),
            // we're only interested in the first
            DEBUG_content("Found ", Rre.numberOfMatches() / 2, " relative URLs:");
            for (int i = 0; i < Rre.numberOfMatches(); i += 2) {
                u = Rre.result(i);

                // can't find a way to negate submatches in PCRE, so it is entirely possible
                // that some absolute URLs have made their way into this list. we don't want them.
                if (u.contains("://"))
                    continue;

                DEBUG_content(u);
                // remove src/href & quotes
                u = u.after("=");
                u.removeWhiteSpace();
                u = u.subString(1, u.length() - 2);

                // create absolute URL
                if (u[0] == '/')
                    u = (*domain) + u;
                else
                    u = currurl + u;

                DEBUG_content("absolute form: ", u );

                if ((((j = foc->inBannedSiteList(u, false, false, false, lastcategory)) != NULL) &&
                     !(lastcategory.contains("ADs")))
                    || (((j = foc->inBannedURLList(u, false, false, false, lastcategory)) != NULL) &&
                      !(lastcategory.contains("ADs")))) {
                    // duplicate checking
                    // checkme: this should really be being done *before* we search the lists.
                    // but because inBanned* methods do some cleaning up of their own, we don't know the form to check against.
                    // we actually want these cleanups do be done before passing to inBanned*/inException* - this would
                    // speed up ConnectionHandler a bit too.
                    founditem = found.find(j);
                    if ((foc->weighted_phrase_mode == 2) && (founditem != found.end())) {
                        founditem->second++;
                    } else {
                        // add the site to the found phrases list
                        found[j] = 1;
                        if (weightedphrase.length() == 0)
                            weightedphrase = "[";
                        else
                            weightedphrase += " ";
                        weightedphrase += j;
                        if (!catinited) {
                            listcategories[-1] = listent(foc->embedded_url_weight, currcat);
                            ourcat = listcategories.find(-1);
                            catinited = true;
                        } else
                            ourcat->second.weight += foc->embedded_url_weight;
                    }
                }
            }
        }
        if (catinited) {
            weighting = ourcat->second.weight;
            weightedphrase += "]";
            DEBUG_content(weightedphrase);
            DEBUG_content("score from embedded URLs: ", ourcat->second.weight );
        }
    }
#endif // END OF LEAVE_OUT_FOR_NOW
#endif

    std::string bannedphrase;
    std::string exceptionphrase;
    String bannedcategory;
    int type, index, weight, time;
    bool allcmatched = true, bannedcombi = false;
    std::string s1;

    // this line here searches for phrases contained in the list - the rest of the code is all sorting
    // through it to find the categories, weightings, types etc. of what has actually been found.
    std::map<std::string, std::pair<unsigned int, int> > found;
    o.lm.l[phraselist]->graphSearch(found, file, filelen);

    // cache reusable iterators
    std::map<std::string, std::pair<unsigned int, int> >::iterator foundend = found.end();
    std::map<std::string, std::pair<unsigned int, int> >::iterator foundcurrent;

    // look for combinations first
    //if banned must wait for exception later
    std::string combifound;
    std::string combisofar;

    std::vector<int>::iterator combicurrent = o.lm.l[phraselist]->combilist.begin();
    std::map<int, listent>::iterator catcurrent;
    int lowest_occurrences = 0;

    while (combicurrent != o.lm.l[phraselist]->combilist.end()) {
        // Grab the current combination phrase part
        index = *combicurrent;
        // Do stuff if what we have is an end marker (end of one list of parts)
        if (index == -2) {
            // Were all the parts in this combination matched?
            if (allcmatched) {
                type = *(++combicurrent);
                // check this time limit against the list of time limits
                time = *(++combicurrent);
                if (not(o.lm.l[phraselist]->checkTimeAtD(time))) {
                    // nope - so don't take any notice of it
#ifdef DEBUG_LOW
                    combicurrent++;
                    cat = (*++combicurrent);
                    DEBUG_content("Ignoring combi phrase based on time limits: ", combisofar, "; ",
                                    o.lm.l[phraselist]->getListCategoryAtD(cat));
#else
                    combicurrent += 2;
#endif
                    combisofar = "";
                } else if (type == -1) { // combination exception
                    isItNaughty = false;
                    isException = true;
                    // Combination exception phrase found:
                    // Combination exception search term found:
                    message_no = searchterms ? 456 : 605;
                    whatIsNaughtyLog = o.language_list.getTranslation(message_no);
                    whatIsNaughtyLog += combisofar;
                    whatIsNaughty = "";
                    ++combicurrent;
                    cat = *(++combicurrent);
                    whatIsNaughtyCategories = o.lm.l[phraselist]->getListCategoryAtD(cat);
                    return;
                } else if (type == 1) { // combination weighting
                    weight = *(++combicurrent);
                    weighting += weight * (foc->weighted_phrase_mode == 2 ? 1 : lowest_occurrences);
                    if (weight > 0) {
                        cat = *(++combicurrent);
                        //category index -1 indicates an uncategorised list
                        if (cat >= 0) {
                            //don't output duplicate categories
                            catcurrent = listcategories.find(cat);
                            if (catcurrent != listcategories.end()) {
                                catcurrent->second.weight += weight * (foc->weighted_phrase_mode == 2 ? 1 : lowest_occurrences);
                            } else {
                                currcat = o.lm.l[phraselist]->getListCategoryAtD(cat);
                                listcategories[cat] = listent(weight, currcat);
                            }
                        }
                    } else {
                        // skip past category for negatively weighted phrases
                        combicurrent++;
                    }
                    if (weightedphrase.length() > 0) {
                        weightedphrase += "+";
                    }
                    weightedphrase += "(";
                    if (weight < 0) {
                        weightedphrase += "-" + combisofar;
                    } else {
                        weightedphrase += combisofar;
                    }

                    DEBUG_content("found combi weighted phrase (", foc->weighted_phrase_mode, "): ", combisofar,
                                 " x", lowest_occurrences, " (per phrase: ",  weight,
                                 ", calculated: ", (weight * (foc->weighted_phrase_mode == 2 ? 1 : lowest_occurrences)), ")" );

                    weightedphrase += ")";
                    combisofar = "";
                } else if (type == 0) { // combination banned
                    bannedcombi = true;
                    combifound += "(" + combisofar + ")";
                    combisofar = "";
                    combicurrent += 2;
                    cat = *(combicurrent);
                    bannedcategory = o.lm.l[phraselist]->getListCategoryAtD(cat);
                }
            } else {
                // We had an end marker, but not all the parts so far were matched.
                // Reset the match flag ready for the next chain, and advance to its first part.
                allcmatched = true;
                combicurrent += 4;
                lowest_occurrences = 0;
            }
        } else {
            // We didn't get an end marker - just an individual part.
            // If all parts in the current chain have been matched so far, look for this one as well.
            if (allcmatched) {
                s1 = o.lm.l[phraselist]->getItemAtInt(index);
                if ((foundcurrent = found.find(s1)) == foundend) {
                    allcmatched = false;
                    combisofar = "";
                } else {
                    if (combisofar.length() > 0) {
                        combisofar += ", ";
                    }
                    combisofar += s1;
                    // also track lowest number of times any one part occurs in the text
                    // as this will correspond to the number of times the whole chain occurs
                    if ((lowest_occurrences == 0) || (lowest_occurrences > foundcurrent->second.second)) {
                        lowest_occurrences = foundcurrent->second.second;
                    }
                }
            }
        }
        // Advance to the next part in the current chain
        combicurrent++;
    }

    // even if we already found a combi ban, we must still wait; there may be non-combi exceptions to follow

    // now check non-combi phrases
    foundcurrent = found.begin();
    while (foundcurrent != foundend) {
        // check time for current phrase
        if (not o.lm.l[phraselist]->checkTimeAt(foundcurrent->second.first)) {
            DEBUG_content("Ignoring phrase based on time limits: ", foundcurrent->first,
                             ", ", o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first) );
            foundcurrent++;
            continue;
        }
        // 0=banned, 1=weighted, -1=exception, 2=combi, 3=weightedcombi
        type = o.lm.l[phraselist]->getTypeAt(foundcurrent->second.first);
        if (type == 0) {
            // if we already found a combi ban, we don't need to know this stuff
            if (!bannedcombi) {
                isItNaughty = true;
                bannedphrase = foundcurrent->first;
                bannedcategory = o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first, &cat);
            }
        } else if (type == 1) {
            // found a weighted phrase - either add one lot of its score, or one lot for every occurrence, depending on phrase filtering mode
            weight = o.lm.l[phraselist]->getWeightAt(foundcurrent->second.first) * (foc->weighted_phrase_mode == 2 ? 1 : foundcurrent->second.second);
            weighting += weight;
            if (weight > 0) {
                currcat = o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first, &cat);
                if (cat >= 0) {
                    //don't output duplicate categories
                    catcurrent = listcategories.find(cat);
                    if (catcurrent != listcategories.end()) {
                        // add one or N times the weight to this category's score
                        catcurrent->second.weight += weight * (foc->weighted_phrase_mode == 2 ? 1 : foundcurrent->second.second);
                    } else {
                        listcategories[cat] = listent(weight, currcat);
                    }
                }
            }

            if (o.naughty.show_weighted_found) {
                if (weightedphrase.length() > 0) {
                    weightedphrase += "+";
                }
                if (weight < 0) {
                    weightedphrase += "-";
                }

                weightedphrase += foundcurrent->first;
            }
            DEBUG_content("found weighted phrase (", foc->weighted_phrase_mode, "): ", foundcurrent->first,
                            " x", foundcurrent->second.second,
                            " (per phrase: ", o.lm.l[phraselist]->getWeightAt(foundcurrent->second.first),
                            ", calculated: ", weight, ")" );
        } else if (type == -1) {
            isException = true;
            isItNaughty = false;
            // Exception phrase found:
            // Exception search term found:
            message_no = searchterms ? 457 : 604;
            whatIsNaughtyLog = o.language_list.getTranslation(message_no);
            whatIsNaughtyLog += foundcurrent->first;
            whatIsNaughty = "";
            whatIsNaughtyCategories = o.lm.l[phraselist]->getListCategoryAt(foundcurrent->second.first, NULL);
            return; // no point in going further
        }
        foundcurrent++;
    }

    DEBUG_content("WEIGHTING: ", weighting );

    // store the lowest negative weighting or highest positive weighting out of all filtering runs, preferring to store positive weightings.
    if ((weighting < 0 && naughtiness <= 0 && weighting < naughtiness) || (naughtiness >= 0 && weighting > naughtiness) || (naughtiness < 0 && weighting > 0)) {
        naughtiness = weighting;
    }

    DEBUG_content("NAUGHTINESS: ", naughtiness );

    // *now* we can safely get down to the whole banning business!

    if (bannedcombi) {
        isItNaughty = true;
        // Banned combination phrase found:
        // Banned combination search term found:
        message_no = searchterms ? 453 : 401;
        log_message_no = searchterms ? 452 : 400;
        whatIsNaughtyLog = o.language_list.getTranslation(log_message_no);
        whatIsNaughtyLog += combifound;
        // Banned combination phrase found.
        // Banned combination search term found.
        whatIsNaughty = o.language_list.getTranslation(message_no );
        whatIsNaughtyCategories = bannedcategory.toCharArray();
        return;
    }

    if (isItNaughty) {
        // Banned phrase found:
        // Banned search term found:
        message_no = searchterms ? 450 : 300;
        whatIsNaughtyLog = o.language_list.getTranslation(message_no);
        whatIsNaughtyLog += bannedphrase;
        // Banned phrase found.
        // Banned search term found.
        whatIsNaughty = o.language_list.getTranslation(searchterms ? 451 : 301);
        whatIsNaughtyCategories = bannedcategory.toCharArray();
        return;
    }

    bool log_it = o.naughty.show_all_weighted_found;
    auto mno = searchterms ? 454 : 402;

    if (weighting > limit) {
        log_it = true;
        isItNaughty = true;
        message_no = mno;
        whatIsNaughty = o.language_list.getTranslation(searchterms ? 455 : 403);
    }

    if(log_it) {
        // Weighted phrase limit of
        // Weighted search term limit of
        whatIsNaughtyLog = o.language_list.getTranslation(mno);
        whatIsNaughtyLog += String(limit).toCharArray();
        whatIsNaughtyLog += " : ";
        whatIsNaughtyLog += String(weighting).toCharArray();
        if (o.naughty.show_weighted_found) {
            whatIsNaughtyLog += " (";
            whatIsNaughtyLog += weightedphrase;
            whatIsNaughtyLog += ")";
        }
        // Weighted phrase limit exceeded.
        // Weighted search term limit exceeded.
        // Generate category list, sorted with highest scoring first.
        bool nonempty = false;
        bool belowthreshold = false;
        String categories;
        std::deque<listent> sortable_listcategories;
        catcurrent = listcategories.begin();
        while (catcurrent != listcategories.end()) {
            sortable_listcategories.push_back(catcurrent->second);
            catcurrent++;
        }
        std::sort(sortable_listcategories.begin(), sortable_listcategories.end());
        std::deque<listent>::iterator k = sortable_listcategories.begin();
        while (k != sortable_listcategories.end()) {
            // if category display threshold is in use, apply it
            if (!belowthreshold && (foc->category_threshold > 0)
                && (k->weight < foc->category_threshold)) {
                whatIsNaughtyDisplayCategories = categories.toCharArray();
                belowthreshold = true;
                usedisplaycats = true;
            }
            if (k->string.length() > 0) {
                if (nonempty)
                    categories += ", ";
                categories += k->string;
                nonempty = true;
            }
            k++;
            // if category threshold is set to show only the top category,
            // everything after the first loop is below the threshold
            if (!belowthreshold && foc->category_threshold < 0) {
                whatIsNaughtyDisplayCategories = categories.toCharArray();
                belowthreshold = true;
                usedisplaycats = true;
            }
        }
        whatIsNaughtyCategories = categories.toCharArray();
    }
        return;
    // whatIsNaughty is what is displayed in the browser
    // whatIsNaughtyLog is what is logged in the log file if at all
}


// strip the URL down to just the IP/hostname, then do an isIPHostname on the result
bool NaughtyFilter::isIPHostnameStrip(String url)
{
    url = url.getHostname();
    if(ch_isiphost.match(url.toCharArray(), Rch_isiphost))
        return false;
    else
        return true;
//    return ldl->fg[0]->isIPHostname(url);
}

String NaughtyFilter::getFlags() {
    String flags = listen_port;
    flags += ":";
    if (!(authrec == nullptr)) {
        if (authrec->is_transparent)
            flags += "T";
        else if (authrec->is_icap)
            flags += "I";
        else {
            if(authrec->is_tlsproxy)
                flags += "L";
            else
                flags += "P";
        }

        if (ismitm)
            flags += "M";
        else if (isconnect)
            flags += "S";
        else if (!authrec->is_icap)
            flags += "H";

        flags += ":";

        flags += authrec->user_source;
        flags += ":";
        flags += authrec->group_source;
    }
    return flags;
}

String NaughtyFilter::get_lastmatch() {
    if (anon_url) {
        return lastmatch.anonimise();
    }
    return lastmatch;
}

String NaughtyFilter::get_logUrl() {
    if (anon_url) {
        String t1 = logurl.before("://");
        String t2 = logurl.after("://");
        t1 += "://";
        t1 += t2.anonimise();
        return t1;
    }
    return logurl;
}

String NaughtyFilter::main_category() {
    String temp = whatIsNaughtyCategories;
    if (temp.contains(",")) {
        temp = temp.before(",");
    }
    if (temp == "-") temp = "";
    temp.toLower();
    return temp;
}

void NaughtyFilter::check_destIP() {
    if (!destIPs_dq.empty())
        return;
    if (!isdirect)
        return;

    int lerr_mess = 0;
    String des_ip;
    if (isiphost)
        des_ip = urldomain;
    if (o.conn.use_original_ip_port && got_orig_ip && (connect_site == urldomain))
        des_ip = orig_ip;

    if (!des_ip.empty()) {

        destIPs_dq.push_back(des_ip);
        destIP = des_ip;
        return;

    } else {
        //dns lookup
        struct addrinfo hints, *infoptr = nullptr;
        memset(&hints, 0, sizeof(addrinfo));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;
        hints.ai_protocol = 0;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;
        bool rt = true;
        while (rt) {
            rt = false;
            int rc = getaddrinfo(connect_site.toCharArray(), NULL, &hints, &infoptr);
            if (rc)  // problem
            {
                DEBUG_debug(" getaddrinfo returned ", String(rc),
                            " for ", connect_site, " ", gai_strerror(rc));

                switch (rc) {
                    case EAI_NONAME:
                        lerr_mess = 207;
                        break;
#ifdef EAI_NODATA
                    case EAI_NODATA:
                        lerr_mess = 208;
                        break;
#endif
                    case EAI_AGAIN:
                        lerr_mess = 209;
                        rt = true;
                        break;
                    case EAI_FAIL:
                        lerr_mess = 210;
                        break;
                    default:
                        lerr_mess = 210;  //TODO this should have it's own message??
                        break;
                }
                //if (rt) continue;
                //else break;
            }
        }
        if (lerr_mess != 0) {
            upfailure = true;
            message_no = lerr_mess;
            whatIsNaughty = o.language_list.getTranslation(lerr_mess);
            whatIsNaughtyLog = whatIsNaughty;
            whatIsNaughtyCategories = "";
            whatIsNaughtyDisplayCategories = "";
            isItNaughty = true;
            blocktype = 3;
            isexception = false;
            isbypass = false;
            DEBUG_debug("Upstream dns failure error is ", lerr_mess);
        } else {
            char t[256];
            struct addrinfo *p;
            for (p = infoptr; p != NULL; p = p->ai_next) {
                getnameinfo(p->ai_addr, p->ai_addrlen, t, sizeof(t), NULL, 0, NI_NUMERICHOST);
                destIPs_dq.push_back(String(t));
            }
            DEBUG_debug("list of ", destIPs_dq.size(), "IPs found");
        }
        freeaddrinfo(infoptr);
    }
}


void NaughtyFilter::set_starttime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    thestart = tv;
    String temp2 = tv.tv_usec / 1000;
    String temp3 = tv.tv_sec;
    if (temp2.length() < 3) {
        temp2.insert(0, 3 - temp2.length(), '0');  // pad to 3 digits
    }
    temp2.insert(0, 1 , '.');
    request_id = thread_id;
    request_id += temp3;
    request_id += temp2;
}
