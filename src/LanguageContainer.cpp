// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "LanguageContainer.hpp"
#include "RegExp.hpp"
#include "String.hpp"
#include "Logger.hpp"

#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <sys/time.h>

// GLOBALS


// IMPLEMENTATION

// wipe loaded language file
void LanguageContainer::reset()
{
    keys.clear();
    values.clear();
}

// look for the translated string corresponding to the given key
//const char *LanguageContainer::getTranslation(const unsigned int index)
//char *LanguageContainer::getTranslation(const unsigned int index)
std::string LanguageContainer::getTranslation(const unsigned int index)
{
    int i;
    int s = keys.size();
    for (i = 0; i < s; i++) {
        if (keys[i] == index) {
            return (std::string) values[i];
        }
    }
        String t = "TRANSLATION KEY ";
        String m(index);
        t +=  m;
        t += " MISSING ";
    return (std::string) t;
}

// open a language file, containing message names (keys) and translated messages (values)
bool LanguageContainer::readLanguageList(const char *filename)
{
    std::string linebuffer; // a string line buffer ;)
    String v;
    String line;
    unsigned int k;
    std::ifstream languagefile(filename, std::ios::in); // open the file for reading
    if (!languagefile.good()) {
        logger_error("Error opening messages file (does it exist?): ", filename);
        return false;
    }
    while (!languagefile.eof()) { // keep going until end of file
        getline(languagefile, linebuffer); // grab a line
        if (linebuffer.length() == 0) {
            continue;
        }
        line = linebuffer.c_str();
        k = line.after("\"").before("\",\"").toInteger();
        v = line.after("\",\"").before("\"");
        if (k >= 0 && v.length() > 0) {
            keys.push_back(k);
            values.push_back(v);
        }
    }
    languagefile.close();
    return true; // successful read
}
