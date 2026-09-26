// RegExp class - search text using regular expressions

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __E2G_HPP_REGEXP
#define __E2G_HPP_REGEXP
#define MAX_SUB_EXPRESSIONS 1024

// INCLUDES

#include <sys/types.h> // needed for size_t used in regex.h

#ifdef HAVE_PCRE
#include <pcreposix.h>
#endif

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#ifdef HAVE_NO_PCRE
#include <regex.h>
#endif

#include <string>
#include <deque>

// DECLARATIONS


class RegResult
{
    public:
    // constructor - set sensible defaults
    RegResult();
    // destructor - delete regexp if compiled
    ~RegResult();

    // how many matches did the last run generate?
    int numberOfMatches();
    // did it generate any at all?
    bool matched();

    // the i'th match from the last run
    std::string result(int i);
    // position of the i'th match in the overall text
    unsigned int offset(int i);
    // length of the i'th match
    unsigned int length(int i);

    // the match results, their positions in the text & their lengths
    std::deque<std::string> results;
    std::deque<unsigned int> offsets;
    std::deque<unsigned int> lengths;

    // have we matched something yet?
    bool imatched;
};

class RegExp
{
    public:
    // constructor - set sensible defaults
    RegExp();
    // destructor - delete regexp if compiled
    ~RegExp();

#ifdef NOTDEFINED
    // copy constructor
    RegExp(const RegExp &r );
#endif


    // compile the given regular expression
    bool comp(const char *exp);
    // match the given text against the pre-compiled expression
    bool match(const char *text, struct RegResult& rs);   //where results are needed
    bool match(const char *text);   //where results are not needed
    bool basematch(const char *text, struct RegResult* rs= nullptr);

    // how many matches did the last run generate?
    // did it generate any at all?

#ifdef NOTDEFINED
    // faster equivalent of STL::Search -  ??? never used??? PIP
    char *search(char *file, char *fileend, char *phrase, char *phraseend);
#endif

    private:

// the expression itself
#ifdef HAVE_PCRE2
    pcre2_code *reg = nullptr;
    int errorcode= 0;
    size_t erroroffset = 0;
    uint32_t pattern_size = 0;
#else
     regex_t reg;
#endif

    // whether it's been pre-compiled
    bool wascompiled = false;

    // the uncompiled form of the expression (checkme: is this only used
    // for debugging purposes?)
    std::string searchstring;
};

#endif
