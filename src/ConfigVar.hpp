//Defines the ConfigVar class, which implements reading options from a file
//into a map

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_CONFIGVAR
#define __HPP_CONFIGVAR

// INCLUDES
#include <cstring>
#include <map>
#include "String.hpp"

// DECLARATIONS
class ConfigVar
{
    public:
    ConfigVar();

    // read the given file, splitting option/value at the given delimiter
    ConfigVar(const char *filename, const char *delimiter = "=");
    int readVar(const char *filename, const char *delimiter = "=");

    // return the value for the named option
    String entry(const char *reference);
    String operator[](const char *reference);

    private:
    // comparison operator (maps are sorted) - true if s1 comes before s2
    struct ltstr {
        bool operator()(String s1, String s2) const
        {
            return strcmp(s1.toCharArray(), s2.toCharArray()) < 0;
        }
    };

    // the map itself - key type, value type, key comparison operator
    std::map<String, String, ltstr> params;
};

#endif
