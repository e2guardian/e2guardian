// RegExp class - search text using regular expressions

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_REGEXP
#define __HPP_REGEXP
#define MAX_SUB_EXPRESSIONS 1024

// INCLUDES

#include <sys/types.h> // needed for size_t used in regex.h

#ifdef HAVE_PCRE
#include <pcreposix.h>
#else
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
    // copy constructor
    RegExp(const RegExp &r );


    // compile the given regular expression
    bool comp(const char *exp);
    // match the given text against the pre-compiled expression
    bool match(const char *text, struct RegResult& rs);

    // how many matches did the last run generate?
    // did it generate any at all?

    // faster equivalent of STL::Search
    char *search(char *file, char *fileend, char *phrase, char *phraseend);

    private:

// the expression itself
     regex_t reg;

    // whether it's been pre-compiled
    bool wascompiled;

    // the uncompiled form of the expression (checkme: is this only used
    // for debugging purposes?)
    std::string searchstring;
};

#endif
