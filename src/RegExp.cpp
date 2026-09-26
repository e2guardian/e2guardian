// RegExp class - search text using regular expressions

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "RegExp.hpp"
#include "Logger.hpp"

#include <cstring>
#include <iostream>


RegResult::RegResult()
    : imatched(false)
{
}


// destructor
RegResult::~RegResult()
{
}

// return the i'th match result
std::string RegResult::result(int i)
{
    if (i >= (signed)results.size() || i < 0) { // reality check
        return ""; // maybe exception?
    }
    return results[i];
}

// get the position of the i'th match result in the overall text
unsigned int RegResult::offset(int i)
{
    if (i >= (signed)offsets.size() || i < 0) { // reality check
        return 0; // maybe exception?
    }
    return offsets[i];
}

// get the length of the i'th match
unsigned int RegResult::length(int i)
{
    if (i >= (signed)lengths.size() || i < 0) { // reality check
        return 0; // maybe exception?
    }
    return lengths[i];
}

// how many matches did the last run generate?
int RegResult::numberOfMatches()
{
    int i = (signed)results.size();
    return i;
}

// did it, in fact, generate any?
bool RegResult::matched()
{
    return imatched; // regexp matches only - not search/replace
}

// constructor - set defaults
RegExp::RegExp()
    : reg(),  wascompiled(false)
{
}
#ifdef NOTDEFINED
// copy constructor   -- This does not appear to be used
RegExp::RegExp(const RegExp &r)
{
//    rs.results.clear();
    //nrs.offsets.clear();
    //nrs.lengths.clear();
    //unsigned int i;
    //for (i = 0; i < rs.results.size(); i++) {
        //nrs.results.push_back(rs.results[i]);
    //}
    //for (i = 0; i < rs.offsets.size(); i++) {
        //nrs.offsets.push_back(rs.offsets[i]);
    //}
    //for (i = 0; i < rs.lengths.size(); i++) {
        //nrs.lengths.push_back(rs.lengths[i]);
    //}

    //nrs.imatched = rs.imatched;
    wascompiled = r.wascompiled;
    searchstring = r.searchstring;
    if (wascompiled == true) {
#ifdef HAVE_PCRE
        if (regcomp(&reg, searchstring.c_str(), REG_ICASE | REG_EXTENDED | REG_DOTALL) != 0) {
            regfree(&reg);
#endif
#ifdef HAVE_NO_PCRE
            if (regcomp(&reg, searchstring.c_str(), REG_ICASE | REG_EXTENDED) != 0) {
                regfree(&reg);
#endif
            //regfree(&reg);
            //rs.imatched = false;
            wascompiled = false;
        }
    }
}
#endif


// destructor - free regex if compiled
RegExp::~RegExp()
{
#ifdef HAVE_PCRE2
    if (wascompiled) {
        pcre2_code_free(reg);
    }
#else
        regfree(&reg);
#endif
}

// compile the given regular expression
bool RegExp::comp(const char *exp)
{
    if (wascompiled) {
#ifdef HAVE_PCRE2
        pcre2_code_free(reg);
#else
        regfree(&reg);
#endif
        wascompiled = false;
    }
    DEBUG_regexp("Compiling ", exp);
#ifdef HAVE_PCRE
    DEBUG_regexp("...with PCRE ");
    if (regcomp(&reg, exp, REG_ICASE | REG_EXTENDED | REG_DOTALL) != 0) { // compile regex
        regfree(&reg);
#endif
#ifdef  HAVE_PCRE2
    DEBUG_regexp("...with PCRE2 ");
    PCRE2_SPTR exp2 = (PCRE2_SPTR) exp;
        reg = pcre2_compile(exp2, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS|PCRE2_EXTENDED|PCRE2_DOTALL,&errorcode,&erroroffset,NULL);
        if(reg == NULL) {
            DEBUG_regexp("Error in comp - code is ", errorcode, " offset is ", erroroffset);
            pcre2_code_free(reg);
#endif
#ifdef HAVE_NO_PCRE
    DEBUG_regexp("...without PCRE ");
    if (regcomp(&reg, exp, REG_ICASE | REG_EXTENDED) != 0) {
        regfree(&reg);
#endif
        return false;
    }
#ifdef HAVE_PCRE2
    DEBUG_regexp("comp OK - code is ", errorcode, " offset is ", erroroffset);
#endif
    wascompiled = true;
    searchstring = exp;
    return true;
}

// match the given text against the pre-compiled expression
bool RegExp::match(const char *text, RegResult &rs)   // where result is needed for regexp replace
{
            return basematch(text, &rs);
}

bool RegExp::match(const char *text)                // where just boolean return is needed
{
    return basematch(text);
}

bool RegExp::basematch(const char *text, RegResult *rs)
{
    if (rs) {
        rs->results.clear();
        rs->offsets.clear();
        rs->lengths.clear();
        rs->imatched = false;
        DEBUG_regexp("regexp results cleared");
    }

    if (!wascompiled) {
        return false;
    }

    if( text == NULL || *text == 0)   // false if text is empty
        return false;

    char *pos = (char *)text;
    int i;
#ifndef HAVE_PCRE2
    unsigned int num_sub_expressions = MAX_SUB_EXPRESSIONS;
#endif
#ifdef HAVE_PCRE2
#ifdef NOTDEFINED
    int rc;
    uint32_t nsb;
    rc = pcre2_pattern_info(reg,PCRE2_INFO_CAPTURECOUNT,&nsb);
    if(rc < 0) {
        DEBUG_regexp("Failed to get pattern count from regexp");
        PCRE2_UCHAR err2[120];
        pcre2_get_error_message(rc, err2,120);
        DEBUG_regexp("pcre2 error is ",err2);
    }
    DEBUG_regexp("pattern count from regexp is ", nsb);
    if(nsb < num_sub_expressions) {
    num_sub_expressions = nsb;
    }
#endif
    if (reg == nullptr) {
        DEBUG_regexp("can't match empty pattern?? ",searchstring);
        return false;
    }

    pcre2_match_data *pmatch;
    pmatch = pcre2_match_data_create_from_pattern(reg, NULL);
    if(pmatch == nullptr) {
        DEBUG_regexp("unable to create pcre2_match_data");
        pcre2_match_data_free(pmatch);
        if (rs) {
            rs->imatched = false;
        }
        return false;
    }
    int rc;
    PCRE2_SPTR text2 = (PCRE2_SPTR) text;
    PCRE2_SIZE text_length = (PCRE2_SIZE)strlen((char *) text2);
    rc = pcre2_match (reg, text2, text_length,0,0,pmatch,NULL);
    if (rc < 0) {
        pcre2_match_data_free(pmatch);
        if (rs) rs->imatched = false;
        DEBUG_regexp("no match for:", searchstring);
        DEBUG_regexp("match target:", text2);
        return false;
    }
    DEBUG_regexp("matched:", searchstring);

#else
    if (reg.re_nsub < num_sub_expressions)
        num_sub_expressions = reg.re_nsub;
    regmatch_t *pmatch = new regmatch_t[num_sub_expressions + 1]; // to hold result
    if (!pmatch) { // if it failed
        if (rs) rs->imatched = false;
        return false;
        // exception?
    }
    if (regexec(&reg, pos, num_sub_expressions + 1, pmatch, 0)) { // run regexdelete[]pmatch;
        delete[] pmatch;
        if (rs) rs->imatched = false;
        DEBUG_regexp("no match for:", searchstring);
        return false; // if no match
    }
#endif
    //size_t matchlen;
    char *submatch;
    unsigned int largestoffset;
    if(not rs) {
#ifdef HAVE_PCRE2
        pcre2_match_data_free(pmatch);
#else
        if (!(pmatch == nullptr)) {
            delete[] pmatch;
            pmatch = nullptr;
        }
#endif
        return true;    // matched but no results needed so just return - stops wasting cpu!
    }
#ifdef HAVE_PCRE2
    PCRE2_SIZE *ovector;
    ovector = pcre2_get_ovector_pointer(pmatch);
    DEBUG_regexp("rc = num matched:", rc);


    while (rc > 0) {
        largestoffset = 0;
        for (i = 0; i < rc; i++) {
            const char* substring_start = text + ovector[2 * i];
            PCRE2_SIZE substring_length = ovector[(2 * i) + 1] - ovector[2 * i];
            DEBUG_regexp("substring_length = ", substring_length);
            submatch = new char[substring_length + 1];
            strncpy(submatch,  substring_start, substring_length);
            submatch[substring_length] = '\0';
            DEBUG_regexp("submatch = ", submatch);
            rs->results.push_back(std::string(submatch));
            rs->offsets.push_back(ovector[2 * i]);
            rs->lengths.push_back(substring_length);
            delete[] submatch;
            if ((ovector[2 * i] + substring_length) > largestoffset) {
                largestoffset = ovector[2 * i] + substring_length;
            }
        }
        if (largestoffset > 0) {
            pos += largestoffset;
            rc = pcre2_match(reg, text2, text_length, largestoffset, 0, pmatch, NULL);
        } else {
            rc = -1;
        }
    }
    rs->imatched = true;
    pcre2_match_data_free(pmatch);
#else
    int error = 0;
    unsigned int matchlen = 0;
    while (error == 0) {
        largestoffset = 0;
        for (i = 0; i <= (signed)num_sub_expressions; i++) {
            if (pmatch[i].rm_so != -1) {
                matchlen = pmatch[i].rm_eo - pmatch[i].rm_so;
                submatch = new char[matchlen + 1];
                strncpy(submatch, pos + pmatch[i].rm_so, matchlen);
                submatch[matchlen] = '\0';
                rs->results.push_back(std::string(submatch));
                rs->offsets.push_back(pmatch[i].rm_so + (pos - text));
                rs->lengths.push_back(matchlen);
                delete[] submatch;
                if ((pmatch[i].rm_so + matchlen) > largestoffset) {
                    largestoffset = pmatch[i].rm_so + matchlen;
                }
            }
        }
        if (largestoffset > 0) {
            pos += largestoffset;
            error = regexec(&reg, pos, num_sub_expressions + 1, pmatch, REG_NOTBOL);
        } else {
            error = -1;
        }
    }
    rs->imatched = true;
    if (pmatch) {
        delete[] pmatch;
        pmatch = nullptr;
    }
#endif
    DEBUG_regexp("match(s) for:", searchstring);
    return true; // match(s) found
}

#ifdef NOTDEFINED
// My own version of STL::search() which seems to be 5-6 times faster
char *RegExp::search(char *file, char *fileend, char *phrase, char *phraseend)
{

    int j, l; // counters
    int p; // to hold precalcuated value for speed
    bool match; // flag
    int qsBc[256]; // Quick Search Boyer Moore shift table (256 alphabet)
    char *k; // pointer used in matching

    int pl = phraseend - phrase; // phrase length
    int fl = (int)(fileend - file) - pl; // file length that could match

    if (fl < pl)
        return fileend; // reality checking
    if (pl > 126)
        return fileend; // reality checking

    // For speed we append the phrase to the end of the memory block so it
    // is always found, thus eliminating some checking.  This is possible as
    // we know an extra 127 bytes have been provided by NaughtyFilter.cpp
    // and also the OptionContainer does not allow phrase lengths greater
    // than 126 chars

    for (j = 0; j < pl; j++) {
        fileend[j] = phrase[j];
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
            return (j + file); // match found at offset j (but could be the
            // copy put at fileend)
        }
        j += qsBc[(unsigned char)file[j + pl]]; // shift
    }
    return fileend; // should never get here as it should always match
}
#endif
