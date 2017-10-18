// ListContainer - class for both item and phrase lists

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include <syslog.h>
#include <algorithm>
#include "ListContainer.hpp"
#include "OptionContainer.hpp"
#include "RegExp.hpp"
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/time.h>
#include <list>

// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;

// DEFINES

#define ROOTNODESIZE 260
#define MAXROOTLINKS ROOTNODESIZE - 4
#define GRAPHENTRYSIZE 64
#define MAXLINKS GRAPHENTRYSIZE - 4
#define ROOTOFFSET ROOTNODESIZE - GRAPHENTRYSIZE

// IMPLEMENTATION

// Constructor - set default values
ListContainer::ListContainer()
    : refcount(0), parent(false), filedate(0), used(false), bannedpfiledate(0), exceptionpfiledate(0), weightedpfiledate(0), blanketblock(false), blanket_ip_block(false), blanketsslblock(false), blanketssl_ip_block(false), sourceisexception(false), sourcestartswith(false), sourcefilters(0), data(NULL), current_graphdata_size(0), realgraphdata(NULL), maxchildnodes(0), graphitems(0), data_length(0), data_memory(0), items(0), isSW(false), issorted(false), graphused(false), force_quick_search(false),
    /*sthour(0), stmin(0), endhour(0), endmin(0),*/ istimelimited(false)
{
}

// delete the memory block when the class is destryed
ListContainer::~ListContainer()
{
    reset();
}

// for both types of list - clear & reset all values
void ListContainer::reset()
{
    free(data);
    if (graphused)
        free(realgraphdata);
    // dereference this and included lists
    // - but not if the reason we're being
    // deleted is due to deletion (this will
    // only happen due to list garbage
    // collection, at which point the list
    // ref should already be zero)
    if (refcount > 0) {
        --refcount;
#ifdef DGDEBUG
        std::cout << "de-reffing " << sourcefile << " due to manual list reset, refcount: " << refcount << std::endl;
#endif
        for (size_t i = 0; i < morelists.size(); ++i)
            o.lm.deRefList(morelists[i]);
    }
    data = NULL;
    realgraphdata = NULL;
    maxchildnodes = 0;
    graphitems = 0;
    data_length = 0;
    data_memory = 0;
    items = 0;
    isSW = false;
    issorted = false;
    graphused = false;
    force_quick_search = 0;
    /*sthour = 0;
	stmin = 0;
	endhour = 0;
	endmin = 0;
	days = "";
	timetag = "";*/
    category = "";
    istimelimited = false;
    combilist.clear();
    slowgraph.clear();
    list.clear();
    lengthlist.clear();
    weight.clear();
    itemtype.clear();
    timelimitindex.clear();
    morelists.clear();
    timelimits.clear();
    listcategory.clear();
    categoryindex.clear();
    used = false;
    parent = false;
    bannedpfile = "";
    exceptionpfile = "";
    weightedpfile = "";
    bannedpfiledate = 0;
    exceptionpfiledate = 0;
    weightedpfiledate = 0;
}

// for item lists - during a config reload, can we simply retain the already loaded list?
bool ListContainer::previousUseItem(const char *filename, bool startswith, int filters)
{
    String f(filename);
    if (f == sourcefile && startswith == sourcestartswith && filters == sourcefilters) {
        return true;
    }
    return false;
}

// for phrase lists - read in the given file, which may be an exception list
// inherit category and time limits from parent
bool ListContainer::readPhraseList(const char *filename, bool isexception, int catindex, int timeindex, bool incref)
{
    // only increment refcount on first read, not read of included files
    // (includes get amalgamated, unlike item lists)
    if (incref)
        ++refcount;
    sourcefile = filename;
    sourceisexception = isexception;
    std::string linebuffer; // a string line buffer ;)
    String temp; // a String for temporary manipulation
    String line;
    String lcat;
    size_t len = 0;
    try {
        len = getFileLength(filename);
    } catch (std::runtime_error &e) {
        if (!is_daemonised) {
            std::cerr << "Error reading file (does it exist?) " << filename << ": " << e.what() << std::endl;
        }
        syslog(LOG_ERR, "Error reading file (does it exist?) %s: %s", filename, e.what());
        return false;
    }
    if (len < 2) {
        return true; // its blank - perhaps due to webmin editing
        // just return
    }
    filedate = getFileDate(filename);
    increaseMemoryBy(len + 2); // Allocate some memory to hold file
    std::ifstream listfile(filename, std::ios::in); // open the file for reading
    if (!listfile.good()) {
        if (!is_daemonised) {
            std::cerr << "Error opening file (does it exist?): " << filename << std::endl;
        }
        syslog(LOG_ERR, "Error opening file (does it exist?): %s", filename);
        return false;
    }
    lcat = "";
    bool caseinsensitive = true;
    while (!listfile.eof()) { // keep going until end of file
        getline(listfile, linebuffer); // grab a line
        if (linebuffer.length() != 0) { // sanity checking
            line = linebuffer.c_str();
            line.removeWhiteSpace();
            // convert to lowercase - unless this is, for example,
            // a phraselist in an odd character encoding which has
            // been marked as not to be converted
            if (caseinsensitive)
                line.toLower();
            if (line.startsWith("<"))
                readPhraseListHelper(line, isexception, catindex, timeindex);
            // handle included list files
            else if (line.startsWith(".")) {
                temp = line.after(".include<").before(">");
                if (temp.length() > 0) {
                    if (!readPhraseList(temp.toCharArray(), isexception, catindex, timeindex, false)) {
                        listfile.close();
                        return false;
                    }
                }
            }
            // phrase lists can be categorised (but not time limited)
            else if (line.startsWith("#listcategory:")) {
                //use the original line so as to preserve case in category names
                temp = linebuffer.c_str();
                lcat = temp.after("\"").before("\"");
                // this serves two purposes: returning the index of the category string
                // if it is already in our category list, and adding it to the list (also
                // returning index) if it is not.
                catindex = getCategoryIndex(&lcat);
#ifdef DGDEBUG
                std::cout << "List category: " << lcat << std::endl;
                std::cout << "Category list index: " << catindex << std::endl;
#endif
            }
            // phrase lists can also be marked as not to be case-converted,
            // to aid support for exotic character encodings
            else if (line.startsWith("#noconvert")) {
#ifdef DGDEBUG
                std::cout << "List flagged as not to be case-converted" << std::endl;
#endif
                caseinsensitive = false;
            }
            // Read in time tags; set timeindex to the ID of the new tag
            else if (line.startsWith("#time: ")) { // see if we have a time tag
                TimeLimit tl;
                if (!readTimeTag(&line, tl)) {
                    return false;
                }
                timelimits.push_back(tl);
                timeindex = timelimits.size() - 1;
#ifdef DGDEBUG
                std::cout << "Found time limit on phrase list. Now have " << timelimits.size() << " limits on this list (including parents)." << std::endl;
#endif
                continue;
            }
        }
    }
    listfile.close();
    return true; // successful read
}

// for phrase lists - helper function for readPhraseList
void ListContainer::readPhraseListHelper(String line, bool isexception, int catindex, int timeindex)
{
    // read in weighting value, if there
    int weighting = line.after("><").before(">").toInteger();
    // defaults to 0
    int type;
    if (weighting != 0) {
        // this is a weighted phrase
        type = 1;
        line = line.before("><") + ">";
    } else {
        if (isexception) {
            // this is an exception phrase
            type = -1;
        } else {
            type = 0;
        }
    }

    if (line.after(">,").length() > 2) {
        // push type & weighting for all phrases on this line onto the combi list
        while (line.length() > 2) {
            line = line.after("<");
            // combination banned, weighted, or exception
            readPhraseListHelper2(line.before(">"), type + 11, weighting, catindex, timeindex);
            line = line.after(">,");
        }
        // end of combi marker
        readPhraseListHelper2("", type + 21, weighting, catindex, timeindex);
    } else {
        line = line.after("<").before(">");
        // push type & weighting for this individual phrase onto combi list (not combination phrase)
        readPhraseListHelper2(line, type, weighting, catindex, timeindex);
    }
}

// for phrase lists - push phrase, type, weighting & category onto combi list
void ListContainer::readPhraseListHelper2(String phrase, int type, int weighting, int catindex, int timeindex)
{
    // -1=exception
    // 0=banned
    // 1=weighted
    // 10 = combination exception
    // 11 = combination banned
    // 12 = combination weighted
    // 20,21,22 = end of combi marker

    if (type > 19) {
        combilist.push_back(-2); // mark an end of a combi
        combilist.push_back(type - 21); // store the combi type
        combilist.push_back(timeindex); // store the combi timtime limitt
        combilist.push_back(weighting); // store the combi weight
        combilist.push_back(catindex); // store the combi category
        return;
    }

    if (phrase.length() > 127) {
        if (!is_daemonised) {
            std::cerr << "Phrase length too long, truncating: " << phrase << std::endl;
        }
        syslog(LOG_ERR, "Phrase length too long, truncating: %s", phrase.toCharArray());
        phrase = phrase.subString(0, 127);
    }

    if (phrase.length() < 1) { // its too small to use
        return;
    }

    if (type < 10) {
        if (!addToItemListPhrase(phrase.toCharArray(), phrase.length(), type, weighting, false, catindex, timeindex)) {
            if (!is_daemonised) {
                std::cerr << "Duplicate phrase, dropping: " << phrase << std::endl;
            }
            syslog(LOG_ERR, "Duplicate phrase, dropping: %s", phrase.toCharArray());
        }
        return;
    }
    // must be a combi or end marker if got here

    // must be a combi if got here

    addToItemListPhrase(phrase.toCharArray(), phrase.length(), type, weighting, true, catindex, timeindex);
}

// for item lists - add phrases to list proper
bool ListContainer::addToItemListPhrase(const char *s, size_t len, int type, int weighting, bool combi, int catindex, int timeindex)
{
    list.push_back(data_length);
    lengthlist.push_back(len);
    for (size_t i = 0; i < len; i++) {
        data[data_length + i] = s[i];
    }
    data[data_length + len] = 0;
    data_length += len + 1;
    if (combi) {
        // if this is a combination item, store the ID of the current item on the combi list
        combilist.push_back(items);
    }
    items++;
    weight.push_back(weighting);
    itemtype.push_back(type);
    categoryindex.push_back(catindex);
    timelimitindex.push_back(timeindex);
    return true;
}

bool ListContainer::ifsreadItemList(std::ifstream *input, int len, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters)
{
    RegExp re;
    re.comp("^.*\\:[0-9]+\\/.*");
    RegResult Rre;
#ifdef DGDEBUG
    if (filters != 32)
        std::cout << "Converting to lowercase" << std::endl;
#endif
    increaseMemoryBy(len + 2); // Allocate some memory to hold file
    String temp, inc, hostname, url;
    //char linebuffer[2048];
    char linebuffer[20000];    // increased to allow checking of line length
    // NOTE: should check for errors instead but input->fail() always seems to
    // be true after first failure and input->clear() does not appear to work
    //  - for future investigation

   // bool skip = false;
    while (!input->eof()) {
        input->getline(linebuffer, sizeof(linebuffer));
     //   if (input->fail()) {
     //       skip = true;
      //      syslog(LOG_ERR, "Line input failure" );
       //     input->clear();
        //    break;
        //}
        //if (skip) {
          //  skip = false;
           // continue;
        //}
        temp = linebuffer;
        if (temp.length() < 2)
            continue; // its jibberish
        if (temp.length() > 2048) {
            temp.limitLength(100);
            syslog(LOG_ERR, "Line too long in list file - ignored %s....", temp.toCharArray() );
            continue;
        }

        //item lists (URLs, domains) can be both categorised and time-limited
        if (linebuffer[0] == '#') {
            if (temp.startsWith("#time: ")) { // see if we have a time tag
                if (!readTimeTag(&temp, listtimelimit)) {
                    return false;
                }
                continue;
            } else if (temp.startsWith("#listcategory:")) {
                category = temp.after("\"").before("\"");
#ifdef DGDEBUG
                std::cout << "found item list category: " << category << std::endl;
#endif
                continue;
            } else if (checkendstring && temp.startsWith(endstring)) {
                break;
            }
            continue; // it's a comment
        }

        // blanket block flags
        if (temp.startsWith("**s")) {
            blanketsslblock = true;
            continue;
        } else if (temp.startsWith("**ips")) {
            blanketssl_ip_block = true;
            continue;
        } else if (temp.startsWith("**")) {
            blanketblock = true;
            continue;
        } else if (temp.startsWith("*ip")) {
            blanket_ip_block = true;
            continue;
        }

        // Strip off comments that don't necessarily start at the beginning of a line
        // - but not regular expression comments
        // - or '#' within a URL
        // So only strings starting with ' #' are regarded as comments
        // if the '#' is not at start of line
        //
        // Amended by Philip Pearce - included in e2g first release 2013:
        std::string::size_type commentstart = 1;
        while ((commentstart = temp.find_first_of('#', commentstart)) != std::string::npos) {
            // Don't treat "(?#...)" as a DG comment - it's a regex comment
            // if (temp[commentstart - 1] != '?')
            // Changed to only treat ' #' as an embedded comment
            if (temp[commentstart - 1] == ' ') {
                temp = temp.substr(0, commentstart);
                break;
            }
            ++commentstart;
        }

        temp.removeWhiteSpace(); // tidy up and make it handle CRLF files
        if (temp.startsWith(".Include<")) { // see if we have another list
            if (do_includes) {
                inc = temp.after(".Include<"); // to include
                inc = inc.before(">");
                if (!readAnotherItemList(inc.toCharArray(), startswith, filters)) { // read it
                    return false;
                }
            }
            continue;
        }
        if (temp.endsWith("/")) {
            temp.chop(); // tidy up
        }
        if (temp.startsWith("ftp://")) {
            temp = temp.after("ftp://"); // tidy up
        }
        if (filters == 1) { // remove port addresses
            if (temp.before("/").contains(":")) { // quicker than full regexp
                if (re.match(temp.toCharArray(),Rre)) {
                    hostname = temp.before(":");
                    url = temp.after("/");
                    temp = hostname + "/" + url;
                }
            }
        }
        if (filters != 32) {
            temp.toLower(); // tidy up - but don't make regex lists lowercase!
        }
        if (temp.length() > 0)
            addToItemList(temp.toCharArray(), temp.length()); // add to unsorted list
    }
#ifdef DGDEBUG
    std::cout << "Blanket flags set:" << blanketblock << ":" << blanket_ip_block << ":" << blanketsslblock << ":" << blanketssl_ip_block << std::endl;
#endif
    return true; // successful read
}

bool ListContainer::ifsReadSortItemList(std::ifstream *input, bool checkendstring, const char *endstring, bool do_includes, bool startswith, int filters, const char *filename)
{
    size_t len = 0;
    try {
        len = getFileLength(filename);
    } catch (std::runtime_error &e) {
        if (!is_daemonised) {
            std::cerr << "Error reading file " << filename << ": " << e.what() << std::endl;
        }
        syslog(LOG_ERR, "Error reading file %s: %s", filename, e.what());
        return false;
    }
    bool ret;
    ret = ifsreadItemList(input, len, checkendstring, endstring, do_includes, startswith, filters);
    if (ret) {
        doSort(startswith);
        return true;
    }
    return false;
}

// for item lists - read item list from file. checkme - what is startswith? is it used? what is filters?
bool ListContainer::readItemList(const char *filename, bool startswith, int filters)
{
    ++refcount;
    sourcefile = filename;
    sourcestartswith = startswith;
    sourcefilters = filters;
    std::string linebuffer;
#ifdef DGDEBUG
    std::cout << "Read filename: " << filename << std::endl;
#endif
    // see if cached .process file is available and up to date,
    // or prefercachedlists has been turned on (SG)
    struct stat s;
    filedate = getFileDate(filename);
    size_t len = 0;
    try {
        len = getFileLength(filename);
    } catch (std::runtime_error &e) {
        if (!is_daemonised) {
            std::cerr << "Error reading file " << filename << ": " << e.what() << std::endl;
        }
        syslog(LOG_ERR, "Error reading file %s: %s", filename, e.what());
        return false;
    }
    if (len < 2) {
        return true; // its blank - perhaps due to webmin editing
        // just return
    }
    std::ifstream listfile(filename, std::ios::in);
    if (!listfile.good()) {
        if (!is_daemonised) {
            std::cerr << "Error opening: " << filename << std::endl;
        }
        syslog(LOG_ERR, "Error opening file: %s", filename);
        return false;
    }
    if (!ifsreadItemList(&listfile, len, false, NULL, true, startswith, filters)) {
        listfile.close();
        if (!is_daemonised) {
            std::cerr << "Error reading: " << filename << std::endl;
        }
        syslog(LOG_ERR, "Error reading file: %s", filename);
        return false;
    }
    listfile.close();
    return true; // successful read
}

// for stdin item lists - read item list from stdin
bool ListContainer::readStdinItemList(bool startswith, int filters, const char *startstr)
{
#ifdef DGDEBUG
    if (filters != 32)
        std::cout << "Converting to lowercase" << std::endl;
#endif
    int mem_used = 2; // keep 2 bytes spare??
    bool skip = true;
    sourcestartswith = startswith;
    sourcefilters = filters;
    std::string linebuffer;
    RegExp re;
    re.comp("^.*\\:[0-9]+\\/.*");
    RegResult Rre;
    size_t len = 0;
    increaseMemoryBy(2048); // Allocate some memory to hold list
    if (!std::cin.good()) {
        if (!is_daemonised) {
            std::cerr << "Error reading stdin: " << std::endl;
        }
        syslog(LOG_ERR, "Error reading stdin");
        return false;
    }
    String temp, inc, hostname, url;
    while (!std::cin.eof()) {
        getline(std::cin, linebuffer);
        if (linebuffer.length() < 2)
            continue; // its jibberish

        temp = linebuffer.c_str();

        if (linebuffer[0] == '#') {
            if (skip && temp.startsWith(startstr)) {
                skip = false;
                continue;
            }
            if (temp.startsWith("#ENDLIST")) {
                break; // end of list
            } else {
                continue; // it's a comment
            }
        }

        if (skip)
            continue;

        // Strip off comments that don't necessarily start at the beginning of a line
        std::string::size_type commentstart = 1;
        while ((commentstart = temp.find_first_of('#', commentstart)) != std::string::npos) {
            if (temp[commentstart - 1] == ' ') {
                temp = temp.substr(0, commentstart);
                break;
            }
            ++commentstart;
        }

        temp.removeWhiteSpace(); // tidy up and make it handle CRLF files
        if (temp.endsWith("/")) {
            temp.chop(); // tidy up
        }
        if (temp.startsWith("ftp://")) {
            temp = temp.after("ftp://"); // tidy up
        }
        if (filters == 1) { // remove port addresses
            if (temp.before("/").contains(":")) { // quicker than full regexp
                if (re.match(temp.toCharArray(),Rre)) {
                    hostname = temp.before(":");
                    url = temp.after("/");
                    temp = hostname + "/" + url;
                }
            }
        }
        if (filters != 32) {
            temp.toLower(); // tidy up - but don't make regex lists lowercase!
        }
        if (temp.length() > 0)
            mem_used += temp.length() + 1;
        if (mem_used > data_memory) {
            increaseMemoryBy(2048);
        }
        addToItemList(temp.toCharArray(), temp.length()); // add to unsorted list
    }
    //listfile.close();
    return true; // successful read
}

// for item lists - read nested item lists
bool ListContainer::readAnotherItemList(const char *filename, bool startswith, int filters)
{

    int result = o.lm.newItemList(filename, startswith, filters, false);
    if (result < 0) {
        if (!is_daemonised) {
            std::cerr << "Error opening file: " << filename << std::endl;
        }
        syslog(LOG_ERR, "Error opening file: %s", filename);
        return false;
    }
    morelists.push_back((unsigned)result);
    return true;
}

// for item lists - is this item in the list?
bool ListContainer::inList(const char *string, String &lastcategory)
{
    if (findInList(string, lastcategory) != NULL) {
        return true;
    }
    return false;
}

// for item lists - is an item in the list that ends with this string?
bool ListContainer::inListEndsWith(const char *string, String &lastcategory)
{
    if (isNow()) {
        if (items > 0) {
            if (search(&ListContainer::greaterThanEW, 0, items - 1, string) >= 0) {
                lastcategory = category;
                return true;
            }
        }
        bool rc;
        for (unsigned int i = 0; i < morelists.size(); i++) {
            rc = (*o.lm.l[morelists[i]]).inListEndsWith(string, lastcategory);
            if (rc) {
            //    lastcategory = (*o.lm.l[morelists[i]]).lastcategory;
                return true;
            }
        }
    }
    return false;
}

// for item lists - is an item in the list that starts with this string?
bool ListContainer::inListStartsWith(const char *string, String &lastcategory)
{
    if (isNow()) {
        if (items > 0) {
            if (search(&ListContainer::greaterThanSW, 0, items - 1, string) >= 0) {
                lastcategory = category;
                return true;
            }
        }
        bool rc;
        for (unsigned int i = 0; i < morelists.size(); i++) {
            rc = (*o.lm.l[morelists[i]]).inListStartsWith(string, lastcategory);
            if (rc) {
                //lastcategory = (*o.lm.l[morelists[i]]).lastcategory;
                return true;
            }
        }
    }
    return false;
}

// find pointer to the part of the data array containing this string
char *ListContainer::findInList(const char *string, String &lastcategory)
{
    if (isNow()) {
        if (items > 0) {
            int r;
            if (isSW) {
                r = search(&ListContainer::greaterThanSWF, 0, items - 1, string);
            } else {
                r = search(&ListContainer::greaterThanEWF, 0, items - 1, string);
            }
            if (r >= 0) {
                lastcategory = category;
                return (data + list[r]);
            }
        }
        char *rc;
        for (unsigned int i = 0; i < morelists.size(); i++) {
            rc = (*o.lm.l[morelists[i]]).findInList(string, lastcategory);
            if (rc != NULL) {
                //lastcategory = (*o.lm.l[morelists[i]]).lastcategory;
                return rc;
            }
        }
    }
    return NULL;
}

// find an item in the list which starts with this
char *ListContainer::findStartsWith(const char *string, String &lastcategory)
{
    if (isNow()) {
        if (items > 0) {
            int r = search(&ListContainer::greaterThanSW, 0, items - 1, string);
            if (r >= 0) {
                lastcategory = category;
                return (data + list[r]);
            }
        }
        char *rc;
        for (unsigned int i = 0; i < morelists.size(); i++) {
            rc = (*o.lm.l[morelists[i]]).findStartsWith(string, lastcategory);
            if (rc != NULL) {
                //lastcategory = (*o.lm.l[morelists[i]]).lastcategory;
                return rc;
            }
        }
    }
    return NULL;
}

char *ListContainer::findStartsWithPartial(const char *string, String &lastcategory)
{
    if (isNow()) {
        if (items > 0) {
            int r = search(&ListContainer::greaterThanSW, 0, items - 1, string);
            if (r >= 0) {
                lastcategory = category;
                return (data + list[r]);
            }
            if (r < -1) {
                r = 0 - r - 2;
                lastcategory = category;
                return (data + list[r]); // nearest match
            }
        }
        char *rc;
        for (unsigned int i = 0; i < morelists.size(); i++) {
            rc = (*o.lm.l[morelists[i]]).findStartsWithPartial(string, lastcategory);
            if (rc != NULL) {
                //lastcategory = (*o.lm.l[morelists[i]]).lastcategory;
                return rc;
            }
        }
    }
    return NULL;
}

char *ListContainer::findEndsWith(const char *string, String &lastcategory)
{
    if (isNow()) {
        if (items > 0) {
            int r = search(&ListContainer::greaterThanEW, 0, items - 1, string);
            if (r >= 0) {
                lastcategory = category;
                return (data + list[r]);
            }
        }
        char *rc;
        for (unsigned int i = 0; i < morelists.size(); i++) {
            rc = (*o.lm.l[morelists[i]]).findEndsWith(string, lastcategory);
            if (rc != NULL) {
                //lastcategory = (*o.lm.l[morelists[i]]).lastcategory;
                return rc;
            }
        }
    }
    return NULL;
}

// For phrase lists - grab the text, score and type of a given phrase, based on item number within list
std::string ListContainer::getItemAtInt(int index)
{
    std::string s(data + list[index], lengthlist[index]);
    return s;
}
int ListContainer::getWeightAt(unsigned int index)
{
    return weight[index];
}
int ListContainer::getTypeAt(unsigned int index)
{
    return itemtype[index];
}
// Phrase lists - check whether the current time is within the limit imposed upon the given phrase
bool ListContainer::checkTimeAt(unsigned int index)
{
    if (timelimitindex[index] == -1) {
        return true;
    }
    return isNow(timelimitindex[index]);
}
bool ListContainer::checkTimeAtD(int index)
{
    if (index == -1) {
        return true;
    }
    return isNow(index);
}

struct lessThanEWF : public std::binary_function<const size_t &, const size_t &, bool> {
    bool operator()(const size_t &aoff, const size_t &boff)
    {
        const char *a = data + aoff;
        const char *b = data + boff;
        size_t alen = strlen(a);
        size_t blen = strlen(b);
        size_t apos = alen - 1;
        size_t bpos = blen - 1;
        for (size_t maxlen = ((alen < blen) ? alen : blen); maxlen > 0; apos--, bpos--, maxlen--)
            if (a[apos] > b[bpos])
                return true;
            else if (a[apos] < b[bpos])
                return false;
        if (alen > blen)
            return true;
        else //if (alen < blen)
            return false;
        //return true;  // both equal
    };
    char *data;
};

struct lessThanSWF : public std::binary_function<const size_t &, const size_t &, bool> {
    bool operator()(const size_t &aoff, const size_t &boff)
    {
        const char *a = data + aoff;
        const char *b = data + boff;
        size_t alen = strlen(a);
        size_t blen = strlen(b);
        size_t maxlen = (alen < blen) ? alen : blen;
        for (size_t i = 0; i < maxlen; i++)
            if (a[i] > b[i])
                return true;
            else if (a[i] < b[i])
                return false;
        if (alen > blen)
            return true;
        else //if (alen < blen)
            return false;
        //return true;  // both equal
    };
    char *data;
};

void ListContainer::doSort(const bool startsWith)
{ // sort by ending of line
    for (size_t i = 0; i < morelists.size(); i++)
        (*o.lm.l[morelists[i]]).doSort(startsWith);
    if (items < 2 || issorted)
        return;
    if (startsWith) {
        lessThanSWF lts;
        lts.data = data;
        std::sort(list.begin(), list.end(), lts);
    } else {
        lessThanEWF lte;
        lte.data = data;
        std::sort(list.begin(), list.end(), lte);
    }
    isSW = startsWith;
    issorted = true;
    return;
}


bool ListContainer::makeGraph(bool fqs)
{
    force_quick_search = fqs;
    if (data_length == 0)
        return true;
    long int i;
    // Quick search has been forced on - put all items on the "slow" list and be done with it
    if (force_quick_search) {
        for (i = 0; i < items; i++) {
            // Check to see if the item is a duplicate
            std::string thisphrase = getItemAtInt(i);
            bool found = false;
            unsigned int foundindex = 0;
            for (std::vector<unsigned int>::iterator j = slowgraph.begin(); j != slowgraph.end(); j++) {
                if (getItemAtInt(*j) == thisphrase) {
                    found = true;
                    foundindex = *j;
                    break;
                }
            }
            if (!found) {
                // Not a duplicate - store it
                slowgraph.push_back(i);
            } else {
                // Duplicate - resolve the collision
                //
                // Existing entry must be a combi AND
                // new entry is not a combi so we overwrite the
                // existing values as combi values and types are
                // stored in the combilist
                // OR
                // both are weighted phrases and the new phrase is higher weighted
                // OR
                // the existing phrase is weighted and the new phrase is banned
                // OR
                // new phrase is an exception; exception phrases take precedence
                if ((itemtype[foundindex] > 9 && itemtype[i] < 10) || (itemtype[foundindex] == 1 && itemtype[i] == 1 && (weight[i] > weight[foundindex])) || (itemtype[foundindex] == 1 && itemtype[i] == 0) || itemtype[i] == -1) {
                    itemtype[foundindex] = itemtype[i];
                    weight[foundindex] = weight[i];
                    categoryindex[foundindex] = categoryindex[i];
                    timelimitindex[foundindex] = timelimitindex[i];
                }
            }
        }
        return true;
    }
    std::string s;
    std::string lasts;
    graphused = true;

#ifdef DGDEBUG
    std::cout << "Bytes needed for phrase tree in worst-case scenario: " << (sizeof(int) * ((GRAPHENTRYSIZE * data_length) + ROOTOFFSET))
              << ", starting off with allocation of " << (sizeof(int) * ((GRAPHENTRYSIZE * ((data_length / 3) + 1)) + ROOTOFFSET)) << std::endl;
    prolificroot = false;
    secondmaxchildnodes = 0;
#endif

    // Make a conservative guess at how much memory will be needed - call realloc() as necessary to change what is actually taken
    current_graphdata_size = (GRAPHENTRYSIZE * ((data_length / 3) + 1)) + ROOTOFFSET;
    realgraphdata = (int *)calloc(current_graphdata_size, sizeof(int));
    if (realgraphdata == NULL) {
        syslog(LOG_ERR, "Cannot allocate memory for phrase tree: %s", strerror(errno));
        return false;
    }
    graphitems++;
    std::deque<size_t> sizelist;

    for (i = 0; i < items; i++) {
        sizelist.push_back(i);
    }
    graphSizeSort(0, items - 1, &sizelist);

    for (i = 0; i < items; i++) {
        graphAdd(String(data + list[sizelist[i]], lengthlist[sizelist[i]]), 0, sizelist[i]);
    }

#ifdef DGDEBUG
    std::cout << "Bytes actually needed for phrase tree: " << (sizeof(int) * ((GRAPHENTRYSIZE * graphitems) + ROOTOFFSET)) << std::endl;
    std::cout << "Most prolific node has " << maxchildnodes << " children" << std::endl;
    std::cout << "It " << (prolificroot ? "is" : "is not") << " the root node" << std::endl;
    std::cout << "Second most prolific node has " << secondmaxchildnodes << " children" << std::endl;
#endif

    realgraphdata = (int *)realloc(realgraphdata, sizeof(int) * ((GRAPHENTRYSIZE * graphitems) + ROOTOFFSET));
    if (realgraphdata == NULL) {
        syslog(LOG_ERR, "Cannot reallocate memory for phrase tree: %s", strerror(errno));
        return false;
    }

    int ml = realgraphdata[2];
    int branches;

    for (i = ml - 1; i >= 0; i--) {
        branches = graphFindBranches(realgraphdata[4 + i]);
        if (branches < 12) { // quicker to use B-M on node with few branches
            graphCopyNodePhrases(realgraphdata[4 + i]);
            // remove link to this node and so effectively remove all nodes
            // it links to but don't recover the memory as its not worth it
            for (int j = i; j < ml; j++) {
                realgraphdata[4 + j] = realgraphdata[4 + j + 1];
            }
            realgraphdata[2]--;
        }
    }
    return true;
}

void ListContainer::graphSizeSort(int l, int r, std::deque<size_t> *sizelist)
{
    if (r <= l)
        return;
    size_t e;
    int k;
    size_t v = getItemAtInt((*sizelist)[r]).length();
    int i = l - 1, j = r, p = i, q = r;
    for (;;) {
        while (getItemAtInt((*sizelist)[++i]).length() < v)
            ;
        while (v < getItemAtInt((*sizelist)[--j]).length()) {
            if (j == l)
                break;
        }
        if (i >= j)
            break;
        e = (*sizelist)[i];
        (*sizelist)[i] = (*sizelist)[j];
        (*sizelist)[j] = e;
        if (v == getItemAtInt((*sizelist)[i]).length()) {
            p++;
            e = (*sizelist)[p];
            (*sizelist)[p] = (*sizelist)[i];
            (*sizelist)[i] = e;
        }
        if (v == getItemAtInt((*sizelist)[j]).length()) {
            q--;
            e = (*sizelist)[q];
            (*sizelist)[q] = (*sizelist)[j];
            (*sizelist)[j] = e;
        }
    }
    e = (*sizelist)[i];
    (*sizelist)[i] = (*sizelist)[r];
    (*sizelist)[r] = e;
    j = i - 1;
    i++;
    for (k = l; k <= p; k++, j--) {
        e = (*sizelist)[k];
        (*sizelist)[k] = (*sizelist)[j];
        (*sizelist)[j] = e;
    }
    for (k = r - 1; k >= q; k--, i++) {
        e = (*sizelist)[k];
        (*sizelist)[k] = (*sizelist)[i];
        (*sizelist)[i] = e;
    }
    graphSizeSort(l, j, sizelist);
    graphSizeSort(i, r, sizelist);
}

// find the total number of children a node has, along all branches
int ListContainer::graphFindBranches(unsigned int pos)
{
    int branches = 0;
    int *graphdata;
    if (pos == 0)
        graphdata = realgraphdata;
    else
        graphdata = realgraphdata + ROOTOFFSET;
    int links = graphdata[pos * GRAPHENTRYSIZE + 2];
    for (int i = 0; i < links; i++) {
        branches += graphFindBranches(graphdata[pos * GRAPHENTRYSIZE + 4 + i]);
    }
    if (links > 1) {
        branches += links - 1;
    }

    return branches;
}

// copy all phrases starting from a given root link into the slowgraph
void ListContainer::graphCopyNodePhrases(unsigned int pos)
{
    int *graphdata;
    if (pos == 0)
        graphdata = realgraphdata;
    else
        graphdata = realgraphdata + ROOTOFFSET;
    int links = graphdata[pos * GRAPHENTRYSIZE + 2];
    int i;
    for (i = 0; i < links; i++) {
        graphCopyNodePhrases(graphdata[pos * GRAPHENTRYSIZE + 4 + i]);
    }
    bool found = false;
    unsigned int foundindex = 0;
    unsigned int phrasenumber = graphdata[pos * GRAPHENTRYSIZE + 3];
    std::string thisphrase = getItemAtInt(phrasenumber);
    for (std::vector<unsigned int>::iterator i = slowgraph.begin(); i != slowgraph.end(); i++) {
        if (getItemAtInt(*i) == thisphrase) {
            found = true;
            foundindex = *i;
            break;
        }
    }
    if (!found) {
        slowgraph.push_back(phrasenumber);
    } else {
        // Duplicate - resolve the collision
        //
        // Existing entry must be a combi AND
        // new entry is not a combi so we overwrite the
        // existing values as combi values and types are
        // stored in the combilist
        // OR
        // both are weighted phrases and the new phrase is higher weighted
        // OR
        // the existing phrase is weighted and the new phrase is banned
        // OR
        // new phrase is an exception; exception phrases take precedence
        if ((itemtype[foundindex] > 9 && itemtype[phrasenumber] < 10) || (itemtype[foundindex] == 1 && itemtype[phrasenumber] == 1 && (weight[phrasenumber] > weight[foundindex])) || (itemtype[foundindex] == 1 && itemtype[phrasenumber] == 0) || itemtype[phrasenumber] == -1) {
            itemtype[foundindex] = itemtype[phrasenumber];
            weight[foundindex] = weight[phrasenumber];
            categoryindex[foundindex] = categoryindex[phrasenumber];
            timelimitindex[foundindex] = timelimitindex[phrasenumber];
        }
    }
}

int ListContainer::bmsearch(char *file, off_t fl, const std::string &s)
{
    off_t pl = s.length();
    if (fl < pl)
        return 0; // reality checking
    if (pl > 126)
        return 0; // reality checking

    // must match all
    off_t j, l; // counters
    int p; // to hold precalcuated value for speed
    bool match; // flag
    int qsBc[256]; // Quick Search Boyer Moore shift table (256 alphabet)
    char *k; // pointer used in matching

    int count = 0;

    char *phrase = new char[pl + 1];
    for (j = 0; j < pl; j++) {
        phrase[j] = s[j];
    }
    phrase[pl] = 0;

    // For speed we append the phrase to the end of the memory block so it
    // is always found, thus eliminating some checking.  This is possible as
    // we know an extra 127 bytes have been provided by NaughtyFilter.cpp
    // and also the OptionContainer does not allow phrase lengths greater
    // than 126 chars
    k = file + fl;
    for (j = 0; j < pl; j++) {
        k[j] = s[j];
    }

    // Next we need to make the Quick Search Boyer Moore shift table

    p = pl + 1;
    for (j = 0; j < 256; j++) { // Preprocessing
        qsBc[j] = p;
    }
    for (j = 0; j < pl; j++) { // Preprocessing
        qsBc[(unsigned char)phrase[j]] = pl - j;
    }

    // Now do the searching!

    for (j = 0;;) {
        k = file + j;
        match = true;
        for (l = 0; l < pl; l++) { // quiv, but faster, memcmp()
            if (k[l] != phrase[l]) {
                match = false;
                break;
            }
        }
        if (match) {
            if (j >= fl) {
                break; // is the end of file marker
            }
            count++;
        }
        j += qsBc[(unsigned char)file[j + pl]]; // shift
    }
    delete[] phrase;
    return count;
}

// Format of the data is each entry has GRAPHENTRYSIZE int values with format of:
// [letter][last letter flag][num links][from phrase][link0][link1]...

void ListContainer::graphSearch(std::map<std::string, std::pair<unsigned int, int> > &result, char *doc, off_t len)
{
    off_t i, j, k;
    std::map<std::string, std::pair<unsigned int, int> >::iterator existingitem;

    //do standard quick search on short branches (or everything, if force_quick_search is on)
    for (std::vector<unsigned int>::iterator i = slowgraph.begin(); i != slowgraph.end(); i++) {
        std::string phrase = getItemAtInt(*i);
        j = bmsearch(doc, len, phrase);
        for (k = 0; k < j; k++) {
            existingitem = result.find(phrase);
            if (existingitem == result.end()) {
                result[phrase] = std::pair<unsigned int, int>(*i, 1);
            } else {
                existingitem->second.second++;
            }
        }
    }

    if (force_quick_search || graphitems == 0) {
#ifdef DGDEBUG
        std::cout << "Map (quicksearch) start" << std::endl;
        for (std::map<std::string, std::pair<unsigned int, int> >::iterator i = result.begin(); i != result.end(); i++) {
            std::cout << "Map: " << i->first << " " << i->second.second << std::endl;
        }
        std::cout << "Map (quicksearch) end" << std::endl;
#endif
        return;
    }

    off_t sl;
    off_t ppos;
    off_t currnode;
    int *graphdata = realgraphdata;
    off_t ml;
    char p;
    off_t pos;
    off_t depth;
    // number of links from root node to first letter of phrase
    ml = graphdata[2] + 4;
    // iterate over entire document
    for (i = 0; i < len; i++) {
        // iterate over all children of the root node
        for (j = 4; j < ml; j++) {
            // grab the endpoint of this link
            pos = realgraphdata[j];
            sl = 0;

            // now comes the main graph search!
            // this is basically a depth-first tree search
            depth = 0;
            while (true) {
                // get the address of the link endpoint and the data actually stored at it
                // note that this only works for GRAPHENTRYSIZE == 64
                ppos = pos << 6;
                if (ppos == 0)
                    graphdata = realgraphdata;
                else
                    graphdata = realgraphdata + ROOTOFFSET;
                p = graphdata[ppos];

                // does the character at this string depth match the relevant character in the node we're currently looking at?
                if (p == doc[i + depth]) {
                    // it does!
                    // is this graph node marked as being the end of a phrase?
                    if (graphdata[ppos + 1] == 1) {
                        // it is, so store the pointer to the matched phrase.
                        std::string phrase = getItemAtInt(graphdata[ppos + 3]);
                        existingitem = result.find(phrase);
                        if (existingitem == result.end()) {
                            result[phrase] = std::pair<unsigned int, int>(graphdata[ppos + 3], 1);
                        } else {
                            existingitem->second.second++;
                        }
#ifdef DGDEBUG
                        std::cout << "Found this phrase: " << phrase << std::endl;
#endif
                    }
                    // grab this node's number of children
                    sl = graphdata[ppos + 2];
                    if (sl > 0) {
                        // this is now the node we're interested in looking at the children of
                        currnode = ppos;
                        // zip straight to the first child of the matched node
                        // (this is the magic that makes it depth first)
                        pos = graphdata[ppos + 4];
                        depth++;
                        continue;
                    }
                    // if we just matched a node that has no children,
                    // we can stop searching. there should be no case in
                    // which the node was not also marked as end of phrase.
                    else
                        break;
                }

                if ((--sl) > 0) {
                    // if we get here, we have discounted one child, but
                    // we still have more children to examine from the last matched node.
                    // we don't keep more than one current interesting node - no backtracking
                    // is necessary, as there is only ever one occurrence of a given character as
                    // a branch of a given node.  backtracking would therefore never
                    // trigger a match down a different route than has been taken thus far, so
                    // don't bother.
                    pos = graphdata[currnode + 4 + (graphdata[currnode + 2] - sl)];
                    continue;
                }
                // if we get here, we've discounted all branches at this depth, and the search is over.
                break;
            }
        }
    }
#ifdef DGDEBUG
    std::cout << "Map start" << std::endl;
    for (std::map<std::string, std::pair<unsigned int, int> >::iterator i = result.begin(); i != result.end(); i++) {
        std::cout << "Map: " << i->first << " " << i->second.second << std::endl;
    }
    std::cout << "Map end" << std::endl;
#endif
}

void ListContainer::graphAdd(String s, const int inx, int item)
{
    unsigned char p = s.charAt(0);
    unsigned char c;
    bool found = false;
    String t;
    int i, px;
    int numlinks;
    int *graphdata;
    int *graphdata2 = realgraphdata + ROOTOFFSET;
    if (inx == 0)
        graphdata = realgraphdata;
    else
        graphdata = realgraphdata + ROOTOFFSET;
    //iterate over the input node's immediate children
    for (i = 0; i < graphdata[inx * GRAPHENTRYSIZE + 2]; i++) {
        //grab the character from this child
        c = (unsigned char)graphdata2[(graphdata[inx * GRAPHENTRYSIZE + 4 + i]) * GRAPHENTRYSIZE];
        if (p == c) {
            //it matches the first char of our string!
            //keep searching, starting from here, to see if the entire phrase is already in the graph
            t = s;
            t.lop();
            if (t.length() > 0) {
                graphAdd(t, graphdata[inx * GRAPHENTRYSIZE + 4 + i], item);
                return;
            }
            found = true;

            // this means the phrase is already there
            // as part of an existing phrase

            //check the end of word flag on the child
            px = graphdata2[(graphdata[inx * GRAPHENTRYSIZE + 4 + i]) * GRAPHENTRYSIZE + 1];
            if (px == 1) {
                // the exact phrase is already there
                px = graphdata2[(graphdata[inx * GRAPHENTRYSIZE + 4 + i]) * GRAPHENTRYSIZE + 3];

                // -1=exception
                // 0=banned
                // 1=weighted
                // 10 = combination exception
                // 11 = combination banned
                // 12 = combination weighted
                // 20,21,22 = end of combi marker
                if ((itemtype[px] > 9 && itemtype[item] < 10) || (itemtype[px] == 1 && itemtype[item] == 1 && (weight[item] > weight[px])) || (itemtype[px] == 1 && itemtype[item] == 0) || itemtype[item] == -1) {
                    // exists as a combi entry already
                    // if got here existing entry must be a combi AND
                    // new entry is not a combi so we overwrite the
                    // existing values as combi values and types are
                    // stored in the combilist
                    // OR
                    // both are weighted phrases and the new phrase is higher weighted
                    // OR
                    // the existing phrase is weighted and the new phrase is banned
                    // OR
                    // new phrase is an exception; exception phrases take precedence
                    itemtype[px] = itemtype[item];
                    weight[px] = weight[item];
                    categoryindex[px] = categoryindex[item];
                    timelimitindex[px] = timelimitindex[item];
                }
            }
        }
    }
    // the phrase wasn't already in the list, so add it
    if (!found) {
        i = graphitems;
        graphitems++;
        // Reallocate memory if we're running out
        if (current_graphdata_size < ((GRAPHENTRYSIZE * graphitems) + ROOTOFFSET)) {
            int new_current_graphdata_size = (GRAPHENTRYSIZE * (graphitems + 256)) + ROOTOFFSET;
            realgraphdata = (int *)realloc(realgraphdata, sizeof(int) * new_current_graphdata_size);
            if (realgraphdata == NULL) {
                syslog(LOG_ERR, "Cannot reallocate memory for phrase tree: %s", strerror(errno));
                exit(1);
            }
            memset(realgraphdata + current_graphdata_size, 0, sizeof(int) * (new_current_graphdata_size - current_graphdata_size));
            current_graphdata_size = new_current_graphdata_size;
            graphdata2 = realgraphdata + ROOTOFFSET;
            if (inx == 0)
                graphdata = realgraphdata;
            else
                graphdata = realgraphdata + ROOTOFFSET;
        }
        numlinks = graphdata[inx * GRAPHENTRYSIZE + 2];
        if ((inx == 0) ? ((numlinks + 1) > MAXROOTLINKS) : ((numlinks + 1) > MAXLINKS)) {
            syslog(LOG_ERR, "Cannot load phraselists from this many languages/encodings simultaneously. (more than %d links from this node! [1])", (inx == 0) ? MAXROOTLINKS : MAXLINKS);
            if (!is_daemonised)
                std::cout << "Cannot load phraselists from this many languages/encodings simultaneously. (more than " << ((inx == 0) ? MAXROOTLINKS : MAXLINKS) << " links from this node! [1])" << std::endl;
            exit(1);
        }
        if ((numlinks + 1) > maxchildnodes) {
            maxchildnodes = numlinks + 1;
#ifdef DGDEBUG
            prolificroot = (inx == 0);
#endif
        }
#ifdef DGDEBUG
        else if ((numlinks + 1) > secondmaxchildnodes)
            secondmaxchildnodes = numlinks + 1;
#endif
        graphdata[inx * GRAPHENTRYSIZE + 2]++;
        graphdata[inx * GRAPHENTRYSIZE + 4 + numlinks] = i;
        graphdata2[i * GRAPHENTRYSIZE] = p;
        graphdata2[i * GRAPHENTRYSIZE + 3] = item;
        s.lop();
        // iterate over remaining characters and add child nodes
        while (s.length() > 0) {
            numlinks = graphdata2[i * GRAPHENTRYSIZE + 2];
            if ((inx == 0) ? ((numlinks + 1) > MAXROOTLINKS) : ((numlinks + 1) > MAXLINKS)) {
                syslog(LOG_ERR, "Cannot load phraselists from this many languages/encodings simultaneously. (more than %d links from this node! [2])", (inx == 0) ? MAXROOTLINKS : MAXLINKS);
                if (!is_daemonised)
                    std::cout << "Cannot load phraselists from this many languages/encodings simultaneously. (more than " << ((inx == 0) ? MAXROOTLINKS : MAXLINKS) << " links from this node! [2])" << std::endl;
                exit(1);
            }
            if ((numlinks + 1) > maxchildnodes) {
                maxchildnodes = numlinks + 1;
#ifdef DGDEBUG
                prolificroot = (inx == 0);
#endif
            }
#ifdef DGDEBUG
            else if ((numlinks + 1) > secondmaxchildnodes)
                secondmaxchildnodes = numlinks + 1;
#endif
            graphdata2[i * GRAPHENTRYSIZE + 2]++;
            graphdata2[i * GRAPHENTRYSIZE + 4 + numlinks] = i + 1;
            i++;
            graphitems++;
            // Reallocate memory if we're running out
            if (current_graphdata_size < ((GRAPHENTRYSIZE * graphitems) + ROOTOFFSET)) {
                int new_current_graphdata_size = (GRAPHENTRYSIZE * (graphitems + 256)) + ROOTOFFSET;
                realgraphdata = (int *)realloc(realgraphdata, sizeof(int) * new_current_graphdata_size);
                if (realgraphdata == NULL) {
                    syslog(LOG_ERR, "Cannot reallocate memory for phrase tree: %s", strerror(errno));
                    exit(1);
                }
                memset(realgraphdata + current_graphdata_size, 0, sizeof(int) * (new_current_graphdata_size - current_graphdata_size));
                current_graphdata_size = new_current_graphdata_size;
                graphdata2 = realgraphdata + ROOTOFFSET;
                if (inx == 0)
                    graphdata = realgraphdata;
                else
                    graphdata = realgraphdata + ROOTOFFSET;
            }
            p = s.charAt(0);
            graphdata2[i * GRAPHENTRYSIZE] = p;
            graphdata2[i * GRAPHENTRYSIZE + 3] = item;
            s.lop();
        }
        graphdata2[i * GRAPHENTRYSIZE + 1] = 1;
    }
}

bool ListContainer::readProcessedItemList(const char *filename, bool startswith, int filters)
{
#ifdef DGDEBUG
    std::cout << "reading processed file:" << filename << std::endl;
#endif
    size_t len = 0;
    size_t slen;
    try {
        len = getFileLength(filename);
    } catch (std::runtime_error &e) {
        if (!is_daemonised) {
            std::cerr << "Error reading file " << filename << ": " << e.what() << std::endl;
        }
        syslog(LOG_ERR, "Error reading file %s: %s", filename, e.what());
        return false;
    }
    if (len < 5) {
        if (!is_daemonised) {
            std::cerr << "File too small (less than 5 bytes - is it corrupt?): " << filename << std::endl;
        }
        syslog(LOG_ERR, "%s", "File too small (less than 5 bytes - is it corrupt?):");
        syslog(LOG_ERR, "%s", filename);
        return false;
    }
    increaseMemoryBy(len + 2);
    std::ifstream listfile(filename, std::ios::in);
    if (!listfile.good()) {
        if (!is_daemonised) {
            std::cerr << "Error opening: " << filename << std::endl;
        }
        syslog(LOG_ERR, "Error opening: %s", filename);
        return false;
    }
    std::string linebuffer;
    String temp, inc;
    while (!listfile.eof()) {
        getline(listfile, linebuffer);
        if (linebuffer[0] == '.') {
            temp = linebuffer.c_str();
            if (temp.startsWith(".Include<")) { // see if we have another list
                inc = temp.after(".Include<").before(">"); // to include
                if (!readAnotherItemList(inc.toCharArray(), startswith, filters)) { // read it
                    listfile.close();
                    return false;
                }
                continue;
            }
        } else if (linebuffer[0] == '#') {
            temp = linebuffer.c_str();
            if (temp.startsWith("#time: ")) { // see if we have a time tag
                if (!readTimeTag(&temp, listtimelimit)) {
                    return false;
                }
                continue;
            } else if (temp.startsWith("#listcategory:")) { // see if we have a category
                category = temp.after("\"").before("\"");
#ifdef DGDEBUG
                std::cout << "found item processed list category: " << category << std::endl;
#endif
                continue;
            }
            continue; // it's a comment man
        }
        // blanket block flags
        if (temp.startsWith("**s")) {
            blanketsslblock = true;
            continue;
        } else if (temp.startsWith("**ips")) {
            blanketssl_ip_block = true;
            continue;
        } else if (temp.startsWith("**")) {
            blanketblock = true;
            continue;
        } else if (temp.startsWith("*ip")) {
            blanket_ip_block = true;
            continue;
        }
        slen = linebuffer.length();
        if (slen < 3)
            continue;
        list.push_back(data_length);
        lengthlist.push_back(slen);
        for (size_t i = 0; i < slen; i++) {
            data[data_length + i] = linebuffer[i];
        }
        data[data_length + slen] = 0;
        data_length += slen + 1;
        items++;
    }
    listfile.close();
    return true;
}

void ListContainer::addToItemList(const char *s, size_t len)
{
    list.push_back(data_length);
    lengthlist.push_back(len);
    for (size_t i = 0; i < len; i++) {
        data[data_length + i] = s[i];
    }
    data[data_length + len] = 0;
    data_length += len + 1;
    items++;
}

int ListContainer::search(int (ListContainer::*comparitor)(const char *a, const char *b), int a, int s, const char *p)
{
    if (a > s)
        return (-1 - a);
    int m = (a + s) / 2;
    int r = (this->*comparitor)(p, data + list[m]);
    if (r == 0)
        return m;
    if (r == -1)
        return search(comparitor, m + 1, s, p);
    if (a == s)
        return (-1 - a);
    return search(comparitor, a, m - 1, p);
}

int ListContainer::greaterThanEWF(const char *a, const char *b)
{
    int alen = strlen(a);
    int blen = strlen(b);
    int apos = alen - 1;
    int bpos = blen - 1;
    for (int maxlen = (alen < blen ? alen : blen); maxlen > 0; apos--, bpos--, maxlen--)
        if (a[apos] > b[bpos])
            return 1;
        else if (a[apos] < b[bpos])
            return -1;
    if (alen > blen)
        return 1;
    else if (alen < blen)
        return -1;
    return 0; // both equal
}

int ListContainer::greaterThanSWF(const char *a, const char *b)
{
    int alen = strlen(a);
    int blen = strlen(b);
    int maxlen = alen < blen ? alen : blen;
    for (int i = 0; i < maxlen; i++)
        if (a[i] > b[i])
            return 1;
        else if (a[i] < b[i])
            return -1;
    if (alen > blen)
        return 1;
    else if (alen < blen)
        return -1;
    return 0; // both equal
}

int ListContainer::greaterThanSW(const char *a, const char *b)
{
    int alen = strlen(a);
    int blen = strlen(b);
    int maxlen = alen < blen ? alen : blen;
    for (int i = 0; i < maxlen; i++)
        if (a[i] > b[i])
            return 1;
        else if (a[i] < b[i])
            return -1;

    // if the URLs didn't match and the one the user is browsing to is longer
    // than what we just compared against, we need to compare against longer URLs,
    // but only if the next character is actually part of a folder name rather than a separator.
    // ('cos if it *is* a separator, it doesn't matter that the overall URL is longer, the
    // beginning of it matches a banned URL.)
    if ((alen > blen) && !(a[blen] == '/' || a[blen] == '?' || a[blen] == '&' || a[blen] == '='))
        return 1;

    // if the banned URL is longer than the URL we're checking, the two
    // can't possibly match.
    else if (blen > alen)
        return -1;

    return 0; // both equal
}

int ListContainer::greaterThanEW(const char *a, const char *b)
{
    int alen = strlen(a);
    int blen = strlen(b);
    int apos = alen - 1;
    int bpos = blen - 1;
    for (int maxlen = (alen < blen ? alen : blen); maxlen > 0; apos--, bpos--, maxlen--)
        if (a[apos] > b[bpos])
            return 1;
        else if (a[apos] < b[bpos])
            return -1;
    if (blen > alen)
        return -1;
    return 0; // both equal
}

void ListContainer::increaseMemoryBy(size_t bytes)
{
    if (data_memory > 0) {
        data = (char *)realloc(data, (data_memory + bytes) * sizeof(char));
        memset(data + data_memory, 0, bytes * sizeof(char));
        data_memory += bytes;
    } else {
        free(data);
        data = (char *)calloc(bytes, sizeof(char));
        data_memory = bytes;
    }
}

size_t getFileLength(const char *filename)
{
    struct stat status;
    int rc = stat(filename, &status);
    if (rc < 0)
        throw std::runtime_error(strerror(errno));
    return status.st_size;
}
time_t getFileDate(const char *filename)
{
    struct stat status;
    int rc = stat(filename, &status);
    if (strlen(filename) < 1)
            return 0;
	
    if (rc != 0) {
        if (errno == ENOENT) {
#ifdef DGDEBUG
            std::cout << "Cannot stat file m_time for " << filename << ". stat() returned errno ENOENT." << std::endl;
#endif
            syslog(LOG_ERR, "Error reading %s. Check directory and file permissions. They should be 640 and 750: %s", filename, strerror(errno));
            return 0;
        }
        // If there are permission problems, just reload the file (CN)
        if (errno == EACCES) {
#ifdef DGDEBUG
            std::cout << "Cannot stat file m_time for " << filename << ". stat() returned errno EACCES." << std::endl;
#endif
            syslog(LOG_ERR, "Error reading %s. Check directory and file permissions and ownership. They should be 640 and 750 and readable by the e2guardian user: %s", filename, strerror(errno));
            return 0;
        }
        else {
            if (!is_daemonised) {
                std::cerr << "Error reading " << filename << "Check directory and file permissions and ownership. They should be 750 and 640 and readable by the e2guardian user: " << strerror(errno) << std::endl;
            }
            syslog(LOG_ERR, "Error reading %s. Check directory and file permissions and ownership. They should be 750 and 640 and readable by the e2guardian user: %s", filename, strerror(errno));
            return 0;
            //return sysv_kill(o.pid_filename);
        }
    }
    return status.st_mtime;
}
#ifdef NODEF
time_t getFileDate(const char *filename)
{
    struct stat status;
    int rc = stat(filename, &status);
    if (rc != 0) {
        if (errno == ENOENT)
            return 0;
        else
            throw std::runtime_error(strerror(errno));
    }
    return status.st_mtime;
}
#endif

bool ListContainer::upToDate()
{
    if (getFileDate(sourcefile.toCharArray()) > filedate) {
        return false;
    }

    for (unsigned int i = 0; i < morelists.size(); i++) {
        if (!(*o.lm.l[morelists[i]]).upToDate()) {
            return false;
        }
    }
    return true;
}

bool ListContainer::readTimeTag(String *tag, TimeLimit &tl)
{
#ifdef DGDEBUG
    std::cout << "Found a time tag" << std::endl;
#endif
    unsigned int tsthour, tstmin, tendhour, tendmin;
    String temp((*tag).after("#time: "));
    tsthour = temp.before(" ").toInteger();
    temp = temp.after(" ");
    tstmin = temp.before(" ").toInteger();
    temp = temp.after(" ");
    tendhour = temp.before(" ").toInteger();
    temp = temp.after(" ");
    tendmin = temp.before(" ").toInteger();
    String tdays(temp.after(" "));
    tdays.removeWhiteSpace();
    if (tsthour > 23) {
        if (!is_daemonised) {
            std::cerr << "Time Tag Start Hour over bounds." << std::endl;
        }
        syslog(LOG_ERR, "%s", "Time Tag Start Hour over bounds.");
        return false;
    }
    if (tendhour > 23) {
        if (!is_daemonised) {
            std::cerr << "Time Tag End Hour over bounds." << std::endl;
        }
        syslog(LOG_ERR, "%s", "Time Tag End Hour over bounds.");
        return false;
    }
    if (tstmin > 59) {
        if (!is_daemonised) {
            std::cerr << "Time Tag Start Min over bounds." << std::endl;
        }
        syslog(LOG_ERR, "%s", "Time Tag Start Min over bounds.");
        return false;
    }
    if (tendmin > 59) {
        if (!is_daemonised) {
            std::cerr << "Time Tag End Min over bounds." << std::endl;
        }
        syslog(LOG_ERR, "%s", "Time Tag End Min over bounds.");
        return false;
    }
    if (tdays.length() > 7) {
        if (!is_daemonised) {
            std::cerr << "Time Tag Days over bounds." << std::endl;
        }
        syslog(LOG_ERR, "%s", "Time Tag Days over bounds.");
        return false;
    }
    istimelimited = true;
    tl.sthour = tsthour;
    tl.stmin = tstmin;
    tl.endhour = tendhour;
    tl.endmin = tendmin;
    tl.days = tdays;
    tl.timetag = (*tag);
    return true;
}

// Returns true if the current time is within the limits specified on this list.
// For phrases, the time limit list index must be passed in -
// included lists don't have their own ListContainer, so time limits are stored differently.
bool ListContainer::isNow(int index)
{
    if (!istimelimited) {
        return true;
    }
    TimeLimit &tl = listtimelimit;
    if (index > -1) {
        tl = timelimits[index];
    }
    time_t tnow; // to hold the result from time()
    struct tm *tmnow; // to hold the result from localtime()
    unsigned int hour, min, wday;
    time(&tnow); // get the time after the lock so all entries in order
    tmnow = localtime(&tnow); // convert to local time (BST, etc)
    hour = tmnow->tm_hour;
    min = tmnow->tm_min;
    wday = tmnow->tm_wday;
    // wrap week to start on Monday
    if (wday == 0) {
        wday = 7;
    }
    wday--;
    unsigned char cday = '0' + wday;
    bool matchday = false;
    for (unsigned int i = 0; i < tl.days.length(); i++) {
        if (tl.days[i] == cday) {
            matchday = true;
            break;
        }
    }
    if (!matchday) {
        return false;
    }
    if (hour < tl.sthour) {
        return false;
    }
    if (hour > tl.endhour) {
        return false;
    }
    if (hour == tl.sthour) {
        if (min < tl.stmin) {
            return false;
        }
    }
    if (hour == tl.endhour) {
        if (min > tl.endmin) {
            return false;
        }
    }
#ifdef DGDEBUG
    std::cout << "time match " << tl.sthour << ":" << tl.stmin << "-" << tl.endhour << ":" << tl.endmin << " " << hour << ":" << min << " " << sourcefile << std::endl;
#endif
    return true;
}

int ListContainer::getCategoryIndex(String *lcat)
{
    // where in the category list is our category? if nowhere, add it.
    if ((*lcat).length() < 2) {
#ifdef DGDEBUG
        std::cout << "blank entry index" << std::endl;
#endif
        return 0; // blank entry index
    }
    int l = (signed)listcategory.size();
    int i;
    for (i = 0; i < l; i++) {
        if ((*lcat) == listcategory[i]) {
            return i;
        }
    }
    listcategory.push_back((*lcat));
    return l;
}

String ListContainer::getListCategoryAt(int index, int *catindex)
{
    //category index of -1 indicates uncategorised list
    if ((index >= categoryindex.size()) || (categoryindex[index] < 0)) {
        return "";
    }
    //return category index (allows naughtyfilter to do numeric comparison between categories
    //when doing duplicate search; much faster than string comparison)
    if (catindex != NULL) {
        (*catindex) = categoryindex[index];
    }
    return listcategory[categoryindex[index]];
}

String ListContainer::getListCategoryAtD(int index)
{
    //category index of -1 indicates uncategorised list
    if ((index < 0) || (index >= listcategory.size())) {
        return "";
    }
    return listcategory[index];
}
