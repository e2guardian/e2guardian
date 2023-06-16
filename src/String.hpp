// String - guess what: it's a string class! Cut down version of Java string
// class interface

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_STRING
#define __HPP_STRING

// INCLUDES

#include <iostream>
#include <string>
#include <sys/types.h>
#include "RegExp.hpp"

// DECLARATIONS

class String : public std::string
{
    public:
    String()
        : std::string(){};
    //~String();

    // constructor from c-string
    String(const char *bs)
        : std::string(bs){};
    // construct from c++ string
    String(const std::string &s)
        : std::string(s){};
    // copy constructor
    String(const String &s)
        : std::string(s){};
    // construct string represenations of numbers
    String(const int num);
    String(const long num);
    String(const long unsigned num);
    String(const unsigned int num);
    String(const bool flag);

#ifndef OFFT_COLLISION
    // If large file support is not enabled (and possibly even if it is),
    // the type of off_t may be a typedef of a type for which we already
    // have a constructor. In that case, don't define one which takes an
    // off_t, or we get compiler errors.
    String(const off_t num);
#endif
    // substring constructors
    String(const char *bs, int len)
        : std::string(bs, len){};
    String(const char *bs, int start, int len)
        : std::string(bs + start, len){};

    // operators
    String operator+(const int &i)
    {
        return (*this) + String(i);
    };

    // return c-string
    const char *toCharArray() const
    {
        return (this->c_str());
    };
    // return substring of length l from start
    String subString(int start, int l) const
    {
        return this->substr(start, l);
    };

    // convert to integer/long integer
    int toInteger();
    long int toLong();
    off_t toOffset();
    // return integer from hex string
    long int hexToInteger();
    // case conversions
    void toLower();
    void toUpper();

    // Swap characters
    void swapChar(char old, char newc);

    // decode %xx to characters (checkme: duplicate code?)
    void hexDecode();

    // does the string start/end with this text?
    bool startsWith(const String &s) const;
    bool endsWith(const String &s) const;
    // does this string start with the given text after conversion to lowercase?
    // (pass the search string in in lowercase; only the text being searched
    // is converted)
    bool startsWithLower(const String &s) const;
    // return offset of substring s within the string
    int indexOf(const char *s) const;
    // does it contain this text?
    bool contains(const char *s) const;

    // chop to base dir (for file paths)    
    void baseDir();
    // convert relative path filename to fully pathed
    void fullPath(String &base_dir);

    // index operator mark 2
    unsigned char charAt(int index)
    {
        return (*this)[index];
    };

    // return string following first occurrence of bs
    String after(const char *bs) const;
    // return string preceding first occurrence of bs
    String before(const char *bs) const;
    // search & replace
    void replaceall(const char *what, const char *with);

    // return header value (after ':' and any leading whitespace) - assumes header finishes with '\r'
    bool headerVal();

    // remove character from end/beginning
    void chop();
    void lop();
    // remove leading & trailing whitespace
    void removeWhiteSpace();
    // remove punctuation
    void removePunctuation();
    // remove protocol prefix (e.g. http://)
    void removePTP();
    // get hostname from string as url
    String getHostname();

    // truncate to given length
    int limitLength(unsigned int l);
    // remove all occurrences of char from String
    void removeChar(char c);
    // remove repeated occurrences of this character
    void removeMultiChar(unsigned char c);
    // clean up slashes, trailing dots, etc. in file paths
    void realPath();

    // generate MD5 hash of string (using given salt)
    String md5();
    String md5(const char *salt);

    // Sort search words
    String sort_search();

    // get CN name that is oK for cert from url
    String CN();
    
    //   bool isNull();

    // redact string/url
    String anonimise();

    bool isIp();
};

#endif
