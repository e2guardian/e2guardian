// ListMeta  - super-class for both item and phrase lists

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include <syslog.h>
#include <algorithm>
#include "ListContainer.hpp"
#include "ListMeta.hpp"
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
#include <vector>

// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;
extern thread_local std::string thread_id;

// DEFINES

// Constructor - set default values
ListMeta::ListMeta() {
}

// delete the memory block when the class is destryed
ListMeta::~ListMeta() {
    reset();
}

String ListMeta::list_type(int type) {
    if (type > LIST_TYPE_ERROR || type < 0)
        type = LIST_TYPE_ERROR;
    return type_map[type];
}

//  clear & reset all values
void ListMeta::reset() {
    for (std::vector<struct list_info>::iterator i = list_vec.begin(); i != list_vec.end(); i++) {
        o.lm.deRefList(i->list_ref);
        i->comp.clear();
        i->reg_list_ref.clear();
    }
}

bool ListMeta::load_type(int type, std::deque<String> &list) {
    unsigned int method_type = 0;
    switch (type) {
        case LIST_TYPE_IP :
            method_type = LIST_METHOD_IP;
            break;
        case LIST_TYPE_IPSITE :
            method_type = LIST_METHOD_IP;
            break;
        case LIST_TYPE_SITE :
            method_type = LIST_METHOD_READF_EWS;
            break;
        case LIST_TYPE_URL :
            method_type = LIST_METHOD_READF_SWS;
            break;
        case LIST_TYPE_SEARCH:
            method_type = LIST_METHOD_READF_SWS;
            break;
        case LIST_TYPE_REGEXP_BOOL:
            method_type = LIST_METHOD_REGEXP_BOOL;
            break;
        case LIST_TYPE_REGEXP_REP :
            method_type = LIST_METHOD_REGEXP_REPL;
            break;
        case LIST_TYPE_FILE_EXT:
            method_type = LIST_METHOD_READF_EWS;
            break;
        case LIST_TYPE_MIME:
            method_type = LIST_METHOD_READF_SWS;
            break;
        case LIST_TYPE_TIME:
            method_type = LIST_METHOD_TIME;
            break;
        case LIST_TYPE_MAP:
            method_type = LIST_METHOD_MAP;
            break;
        case LIST_TYPE_IPMAP:
            method_type = LIST_METHOD_IPMAP;
            break;
            // PhraseList types to be added
    }
    bool errors = false;
    int dq_size = list.size();
    for (int i = dq_size - 1; i > -1; i--) { // search backward thru list
        // parse line
        String t;
        t = list[i];
#ifdef E2DEBUG
        std::cerr << thread_id << "reading " << t.toCharArray() << std::endl;
#endif
        String nm, fpath, pwd;
        bool anonlog = o.anonymise_logs;
        bool sitewild = true;
        unsigned int m_no = 0, log_m_no = 0;
        t.removeWhiteSpace();
        t.removeChar('\'');
        t += ",";
        while (t.length() > 0) {
            if (t.startsWith("name=")) {
                nm = t.after("=").before(",");
            } else if (t.startsWith("messageno=")) {
                m_no = t.after("=").before(",").toInteger();
            } else if (t.startsWith("logmessageno=")) {
                log_m_no = t.after("=").before(",").toInteger();
            } else if (t.startsWith("path=")) {
                fpath = t.after("=").before(",");
            } else if (t.startsWith("listdir=")) {
                pwd = t.after("=").before(",");
            } else if (t.startsWith("anonlog=true")) {
                anonlog = true;
            } else if (t.startsWith("sitewild=false")) {
                sitewild = false;
            }
            t = t.after(",");
            t.removeWhiteSpace();
        }
        if (list_exists(nm, type)) {
            syslog(LOG_INFO, "List name %s of this type already defined - ignoring %s", nm.toCharArray(),
                   t.toCharArray());
            errors = true;
            continue;
        }

        list_info rec;
        rec.type = type;
        rec.method_type = method_type;
        rec.name = nm;
        rec.pwd = pwd;
        rec.mess_no = m_no;
        rec.anon_log = anonlog;
        rec.site_wild = sitewild;
        if (log_m_no) {
            rec.log_mess_no = log_m_no;
        } else {
            rec.log_mess_no = m_no;
        }
#ifdef E2DEBUG
        std::cerr << thread_id << "name = " << nm.toCharArray() << " m_no=" << (int) m_no << "log_m_no="
                  << rec.log_mess_no << " path=" << fpath.toCharArray() << std::endl;
#endif

        switch (method_type) {
            case LIST_METHOD_IP:
                if (readFile(fpath.toCharArray(), pwd.toCharArray(), &rec.list_ref, false, nm.toCharArray(), true)) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_IPMAP:
                if (readFile(fpath.toCharArray(), pwd.toCharArray(), &rec.list_ref, false, nm.toCharArray(), true, false, true)) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_MAP:
                if (readFile(fpath.toCharArray(), pwd.toCharArray(), &rec.list_ref, false, nm.toCharArray(), false, false, true)) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_TIME:
                if (readFile(fpath.toCharArray(),  pwd.toCharArray(),&rec.list_ref, false, nm.toCharArray(), false, true)) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_READF_EWS :
                if (readFile(fpath.toCharArray(), pwd.toCharArray(), &rec.list_ref, false, nm.toCharArray())) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_READF_SWS :
                if (readFile(fpath.toCharArray(), pwd.toCharArray(), &rec.list_ref, true, nm.toCharArray())) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_REGEXP_BOOL :
                if (readRegExMatchFile(fpath.toCharArray(), pwd.toCharArray(), nm.toCharArray(), rec.list_ref, rec.comp, rec.source,
                                       rec.reg_list_ref)) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_REGEXP_REPL :
                if (readRegExReplacementFile(fpath.toCharArray(),  pwd.toCharArray(),nm.toCharArray(), rec.list_ref, rec.replace,
                                             rec.comp)) {
                    list_vec.push_back(rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
        }
    }
    if (errors && o.abort_on_missing_list) return false;
    return true;
}


bool ListMeta::list_exists(String name, int type) {
    if (findList(name, (int) type).name != "")
        return true;
    else
        return false;
}

ListMeta::list_info ListMeta::findList(String name, int tp) {
    list_info t;
    list_info *tptr;
    tptr = findListPtr(name, tp);
    if (tptr) {
        t = *tptr;
    } else
        t.list_ref = 0;
    return t;
}

ListMeta::list_info *ListMeta::findListPtr(String name, int tp) {
    list_info *t = nullptr;
    unsigned int type = (unsigned int) tp;
#ifdef E2DEBUG
    std::cerr << thread_id << "Looking for " << name << " type " << type << " in listmeta" << std::endl;
#endif
    for (std::vector<struct list_info>::iterator i = list_vec.begin(); i != list_vec.end(); i++) {
        if (i->name == name && i->type == type) {
#ifdef E2DEBUG
            std::cerr << thread_id << "Found " << i->name << " type " << i->type << " in listmeta" << std::endl;
#endif
            t = &(*i);
            return t;
        }
        // std::cerr << thread_id << "Loop checking " << i->name << " type " << i->type << " in listmeta" << std::endl;
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "Not Found " << name << " type " << type << " in listmeta" << std::endl;
#endif
    return t;
}

unsigned int ListMeta::findListId(String name, int type) {
    list_info t;
    t.list_ref = 0;
    t = findList(name, type);
    return t.list_ref;
}

bool ListMeta::inList(String name, int type, String &tofind, list_result &res) {
    list_info info = findList(name, type);
    return inList(info, tofind, res);
}

bool ListMeta::inList(list_info &info, std::deque<String> &header, list_result &res) {
// this is only used for checking headers
    if (info.name == "") return false;
    int type = info.type;
    //char *match;
    switch (type) {
        case LIST_TYPE_REGEXP_BOOL : {
            int rc = inHeaderRegExp(info, header, res, res.category);
            if (rc == -1) {
                return false;
            } else {
                res.category = o.lm.l[info.reg_list_ref[rc]]->category;
                res.match = info.source[rc];
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
        }
        case LIST_TYPE_REGEXP_REP: {
            if (info.comp.size() == 0)
                return false;
            if (headerRegExpReplace(info, header, res)) {
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            return false;
        }
    }
    return false;
}

bool ListMeta::inList(list_info &info, String &tofind, list_result &res) {
    if (info.name == "") return false;
    int type = info.type;
    const char *match;
   // String match;
    switch (type) {
        case LIST_TYPE_IP:
            match = o.lm.l[info.list_ref]->findInList(tofind.toCharArray(), res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_IPMAP:
        case LIST_TYPE_MAP:
            match = o.lm.l[info.list_ref]->findInList(tofind.toCharArray(), res.category);
            if (match == NULL) {
                return false;
            } else {
                res.result = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_TIME:
            if (o.lm.l[info.list_ref]->isNowInTimelist()) {
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            return false;
            break;
        case LIST_TYPE_IPSITE:
            match = o.lm.l[info.list_ref]->findInList(tofind.toCharArray(), res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_SITE :
            match = inSiteList(tofind, info.list_ref, res.category,info.site_wild);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_URL:
            match = inURLList(tofind, info.list_ref, res.category,info.site_wild);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_SEARCH :
            match = inSearchList(tofind, info.list_ref, res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_MIME:
            match = o.lm.l[info.list_ref]->findInList(tofind.toCharArray(), res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_FILE_EXT:
            match = o.lm.l[info.list_ref]->findEndsWith(tofind.toCharArray(), res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            break;
        case LIST_TYPE_REGEXP_BOOL : {
            int rc = inRegExpURLList(tofind, info.comp, info.reg_list_ref, info.list_ref, res.category);
            if (rc == -1) {
                return false;
            } else {
                res.category = o.lm.l[info.reg_list_ref[rc]]->category;
                res.match = info.source[rc];
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
        }
            break;
        case LIST_TYPE_REGEXP_REP: {
            if (info.comp.size() == 0)
                return false;
            String modified = tofind;
            if (regExp(modified, info.comp, info.replace)) {
                res.result = modified;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                res.anon_log = info.anon_log;
                return true;
            }
            return false;
        }
            break;
    }
    return false;
}

// read in the given file, write the list's ID into the given identifier,
// sort using startsWith or endsWith depending on sortsw, and create a cache file if desired.
// listname is used in error messages.
bool ListMeta::readFile(const char *filename, const char *pwd, unsigned int *whichlist, bool sortsw, const char *listname, bool isip, bool istime, bool ismap) {
    if (strlen(filename) < 3) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Required Listname " << listname << " is not defined" << std::endl;
        }
        syslog(LOG_ERR, "Required Listname %s is not defined", listname);
        return false;
    }
    int res = o.lm.newItemList(filename, pwd, sortsw, 1, true, isip, istime, ismap);
    if (res < 0) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    (*whichlist) = (unsigned) res;
    if (!(*o.lm.l[(*whichlist)]).used) {
        if(!istime) {
          if (sortsw)
            (*o.lm.l[(*whichlist)]).doSort(true);
          else
            (*o.lm.l[(*whichlist)]).doSort(false);
        }
        (*o.lm.l[(*whichlist)]).used = true;
    }
    return true;
}


const char *ListMeta::inSiteList(String &urlp, unsigned int list, String &lastcategory, bool &site_wild) {

    String url = urlp;
    const char *i;
    if (site_wild) {
        while (url.contains(".")) {
            i = (*o.lm.l[list]).findInList(url.toCharArray(), lastcategory);
            if (i != NULL) {
                return i; // exact match
            }
            url = url.after("."); // check for being in higher level domains
        }
    }
    if ((!url.contains(".")) && url.length() > 1) { // allows matching of .tld
        url = "." + url;
    }
    if(url.length() > 2)
    {
        i = (*o.lm.l[list]).findInList(url.toCharArray(), lastcategory);
        if (i != NULL) {
            return i; // exact match
        }
    }
    return NULL; // and our survey said "UUHH UURRGHH"
}

const char *ListMeta::inSearchList(String &words, unsigned int list, String &lastcategory) {
    const char *i = (*o.lm.l[list]).findInList(words.toCharArray(), lastcategory);
    if (i != NULL) {
        return i; // exact match
    }
    return NULL;
}


// look in given URL list for given URL
char *ListMeta::inURLList(String &urlp, unsigned int list, String &lc, bool &site_wild) {
    String url = urlp;
    unsigned int fl;
    char *i;
    String foundurl;
#ifdef E2DEBUG
    std::cerr << thread_id << "inURLList: " << url << std::endl;
#endif
//    url.removeWhiteSpace(); // just in case of weird browser crap
//    url.toLower();
//    url.removePTP(); // chop off the ht(f)tp(s)://
    if (url.contains("/")) {
        String tpath("/");
        tpath += url.after("/");
        url = url.before("/");
        tpath.hexDecode();
        tpath.realPath();
        url += tpath; // will resolve ../ and %2e2e/ and // etc
    }
    if (url.endsWith("/")) {
        url.chop(); // chop off trailing / if any
    }
#ifdef E2DEBUG
    std::cerr << thread_id << "inURLList (processed): " << url << std::endl;
#endif
        while (url.before("/").contains(".")) {
            i = (*o.lm.l[list]).findStartsWith(url.toCharArray(), lc);
            if (i != NULL) {
                foundurl = i;
                fl = foundurl.length();
#ifdef E2DEBUG
                std::cerr << thread_id << "foundurl: " << foundurl << foundurl.length() << std::endl;
            std::cerr << thread_id << "url: " << url << fl << std::endl;
#endif
                if (url.length() > fl) {
                    if (url[fl] == '/' || url[fl] == '?' || url[fl] == '&' || url[fl] == '=') {
                        return i; // matches /blah/ or /blah/foo but not /blahfoo
                    }
                } else {
                    return i; // exact match
                }
           }
            if (!site_wild)
                break;
            url = url.after("."); // check for being in higher level domains
        }
    return NULL;
}

bool ListMeta::isIPHostname(String url) {
    RegResult Rre;
    if (!isiphost.match(url.toCharArray(), Rre)) {
        return true;
    }
    return false;
}

bool ListMeta::precompileregexps() {
    if (!isiphost.comp(".*[a-z|A-Z].*")) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error compiling RegExp isiphost." << std::endl;
        }
        syslog(LOG_ERR, "%s", "Error compiling RegExp isiphost.");
        return false;
    }

    return true;
}

// read regexp url list
bool ListMeta::readRegExMatchFile(const char *filename,const char *list_pwd, const char *listname, unsigned int &listref,
                                  std::deque<RegExp> &list_comp, std::deque<String> &list_source,
                                  std::deque<unsigned int> &list_ref) {
    int result = o.lm.newItemList(filename, list_pwd, true, 32, true);
    if (result < 0) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    listref = (unsigned) result;
    return compileRegExMatchFile(listref, list_comp, list_source, list_ref);
}

// NOTE TO SELF - MOVE TO LISTCONTAINER TO SOLVE FUE2E
// compile regexp url list
bool ListMeta::compileRegExMatchFile(unsigned int list, std::deque<RegExp> &list_comp,
                                     std::deque<String> &list_source, std::deque<unsigned int> &list_ref) {
    for (unsigned int i = 0; i < (*o.lm.l[list]).morelists.size(); i++) {
        if (!compileRegExMatchFile((*o.lm.l[list]).morelists[i], list_comp, list_source, list_ref)) {
            return false;
        }
    }
    RegExp r;
    bool rv = true;
    int len = (*o.lm.l[list]).getListLength();
    String source;
    for (int i = 0; i < len; i++) {
        source = (*o.lm.l[list]).getItemAtInt(i).c_str();
        rv = r.comp(source.toCharArray());
        if (rv == false) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error compiling regexp:" << source << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error compiling regexp:");
            syslog(LOG_ERR, "%s", source.toCharArray());
            return false;
        }
        list_comp.push_back(r);
        list_source.push_back(source);
        list_ref.push_back(list);
    }
    (*o.lm.l[list]).used = true;
    return true;
}

// content and URL regular expression replacement files
bool ListMeta::readRegExReplacementFile(const char *filename, const char *list_pwd, const char *listname, unsigned int &listid,
                                        std::deque<String> &list_rep, std::deque<RegExp> &list_comp) {
    int result = o.lm.newItemList(filename,list_pwd, true, 32, true);
    if (result < 0) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    listid = (unsigned) result;
    if (!(*o.lm.l[listid]).used) {
        //(*o.lm.l[listid]).doSort(true);
        (*o.lm.l[listid]).used = true;
    }
    RegExp r;
    bool rv = true;
    String regexp;
    String replacement;
    for (int i = 0; i < (*o.lm.l[listid]).getListLength(); i++) {
        regexp = (*o.lm.l[listid]).getItemAtInt(i).c_str();
        replacement = regexp.after("\"->\"");
        while (!replacement.endsWith("\"")) {
            if (replacement.length() < 2) {
                break;
            }
            replacement.chop();
        }
        replacement.chop();
        regexp = regexp.after("\"").before("\"->\"");
        if (regexp.length() < 1) { // allow replace with nothing
            continue;
        }
        rv = r.comp(regexp.toCharArray());
        if (rv == false) {
            if (!is_daemonised) {
                std::cerr << thread_id << "Error compiling regexp: " << (*o.lm.l[listid]).getItemAtInt(i) << std::endl;
            }
            syslog(LOG_ERR, "%s", "Error compiling regexp: ");
            syslog(LOG_ERR, "%s", (*o.lm.l[listid]).getItemAtInt(i).c_str());
            return false;
        }
        list_comp.push_back(r);
        list_rep.push_back(replacement);
    }
    return true;
}

// is this URL in the given regexp URL list?
int ListMeta::inRegExpURLList(String &urlin, std::deque<RegExp> &list_comp, std::deque<unsigned int> &list_ref,
                              unsigned int list, String &lastcategory) {
#ifdef REDEBUG
    std::cerr << thread_id << "inRegExpURLList: " << urlin << std::endl;
#endif
    // check parent list's time limit
    if (o.lm.l[list]->isNow()) {
        RegResult Rre;
        String url = urlin;
        url.removeWhiteSpace(); // just in case of weird browser crap
        url.toLower();

        // whilst it would be nice to have regexes be able to match the PTP,
        // it has been assumed for too long that the URL string does not start with one,
        // and we don't want to break regexes that look explicitly for the start of
        // the string. changes here have therefore been reverted. 2005-12-07
        url.removePTP();
        if (url.contains("/")) {
            String tpath("/");
            tpath += url.after("/");
            url = url.before("/");
            tpath.hexDecode();
            tpath.realPath();
            url += tpath; // will resolve ../ and %2e2e/ and // etc
        }
        if (url.endsWith("/")) {
            url.chop(); // chop off trailing / if any
        }
// re-add the PTP
/*if (ptp.length() > 0)
			url = ptp + "//" + url;*/
#ifdef REDEBUG
        std::cerr << thread_id << "inRegExpURLList (processed): " << url << std::endl;
#endif
        unsigned int i = 0;
        for (std::deque<RegExp>::iterator j = list_comp.begin(); j != list_comp.end(); j++) {
            if (o.lm.l[list_ref[i]]->isNow()) {
                if (j->match(url.toCharArray(), Rre))
                    return i;
            }
#ifdef REDEBUG
            else
                std::cerr << thread_id << "Outside included regexp list's time limit" << std::endl;
#endif
            i++;
        }
    }
#ifdef REDEBUG
    else {
        std::cerr << thread_id << "Outside top level regexp list's time limit" << std::endl;
    }
#endif
    return -1;
}

// Does a regexp search and replace.
// urlRegExp Code originally from from Ton Gorter 2004
bool ListMeta::regExp(String &line, std::deque<RegExp> &regexp_list, std::deque<String> &replacement_list) {
    RegExp *re;
    RegResult Rre;
    String replacement;
    String repstr;
    String newLine;
    bool linemodified = false;
    unsigned int i;
    unsigned int j, k;
    unsigned int s = regexp_list.size();
    unsigned int matches, submatches;
    unsigned int match;
    unsigned int srcoff;
    unsigned int nextoffset;
    unsigned int matchlen;
    unsigned int oldlinelen;

    if ((line.empty()) || line.length() < 3)
        return false;

    // iterate over our list of precompiled regexes
    for (i = 0; i < s; i++) {
        newLine = "";
        re = &(regexp_list[i]);
        if (re->match(line.toCharArray(), Rre)) {
            repstr = replacement_list[i];
            matches = Rre.numberOfMatches();

            srcoff = 0;

            for (j = 0; j < matches; j++) {
                nextoffset = Rre.offset(j);
                matchlen = Rre.length(j);

                // copy next chunk of unmodified data
                if (nextoffset > srcoff) {
                    newLine += line.subString(srcoff, nextoffset - srcoff);
                    srcoff = nextoffset;
                }

                // Count number of submatches (brackets) in replacement string
                for (submatches = 0; j + submatches + 1 < matches; submatches++)
                    if (Rre.offset(j + submatches + 1) + Rre.length(j + submatches + 1) > srcoff + matchlen)
                        break;

                // \1 and $1 replacement
                replacement = "";
                for (k = 0; k < repstr.length(); k++) {
                    // find \1..\9 and $1..$9 and fill them in with submatched strings
                    if ((repstr[k] == '\\' || repstr[k] == '$') && repstr[k + 1] >= '1' && repstr[k + 1] <= '9') {
                        match = repstr[++k] - '0';
                        if (match <= submatches) {
                            replacement += Rre.result(j + match).c_str();
                        }
                    } else {
                        // unescape \\ and \$, and add non-backreference characters to string
                        if (repstr[k] == '\\' && (repstr[k + 1] == '\\' || repstr[k + 1] == '$'))
                            k++;
                        replacement += repstr.subString(k, 1);
                    }
                }

                // copy filled in replacement string
                newLine += replacement;
                srcoff += matchlen;
                j += submatches;
            }
            oldlinelen = line.length();
            if (srcoff < oldlinelen) {
                newLine += line.subString(srcoff, oldlinelen - srcoff);
            }
#ifdef REDEBUG
            std::cerr << thread_id << "Line modified! (" << line << " -> " << newLine << ")" << std::endl;
#endif
            // copy newLine into line and continue with other regexes
            line = newLine;
            linemodified = true;
        }
    }

    return linemodified;

}

bool ListMeta::headerRegExpReplace(ListMeta::list_info &listi, std::deque<String> &header, list_result &res) {
    // exit immediately if list is empty
    if (not listi.comp.size())
        return false;
    bool result = false;
    for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
#ifdef REDEBUG
        std::cerr << thread_id << "Starting header reg exp replace: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        bool chop = false;
        if (i->endsWith("\r")) {
            i->chop();
            chop = true;
        }
        result |= regExp(*i, listi.comp, listi.replace);
        if (chop)
            i->append("\r");
    }
#ifdef REDEBUG
    for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++)
        std::cerr << thread_id << "Starting header reg exp replace result: " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    return result;
}

int ListMeta::inHeaderRegExp(list_info &listi, std::deque<String> &header, list_result &res, String &lastcategory) {
    // exit immediately if list is empty
    if (not listi.comp.size())
        return false;
    int result = -1;
    for (std::deque<String>::iterator i = header.begin(); i != header.end(); i++) {
#ifdef REDEBUG
        std::cerr << thread_id << "Starting header reg exp check " << *i << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        bool chop = false;
        if (i->endsWith("\r")) {
            i->chop();
            chop = true;
        }
        result = inRegExpURLList(*i, listi.comp, listi.reg_list_ref, listi.list_ref, lastcategory);
        if (chop)
            i->append("\r");
        if (result > -1) {
            res.category = lastcategory;
            //res.match =     TODO add the info
            break;
        }
    }
    return result;
}

