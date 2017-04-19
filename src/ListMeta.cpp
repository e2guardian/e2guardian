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

// DEFINES

// Constructor - set default values
ListMeta::ListMeta()
{
}

// delete the memory block when the class is destryed
ListMeta::~ListMeta()
{
    reset();
}

// for both types of list - clear & reset all values
void ListMeta::reset()
{
}

bool ListMeta::load_type(int type, std::deque<String> list) {
    int method_type;
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
            method_type = LIST_METHOD_READF_EWS;
            break;
            // PhraseList types to be added
                }
    bool errors = false;
    for (std::deque<String>::iterator i = list.end(); i != list.begin(); --i) { // search backward thru list
        // parse line
        String t = *i;
        String nm, fpath;
        unsigned int m_no, log_m_no;
        t.removeWhiteSpace();
        while (t.length() > 0) {
            if (t.startsWith("name=")) {
                nm = t.after("=").before(",");
            } else if (t.startsWith("messageno=")) {
                m_no = t.after("=").before(",").toInteger();
            } else if (t.startsWith("logmessageno=")) {
            log_m_no = t.after("=").before(",").toInteger();
            } else if (t.startsWith("path=")) {
                fpath = t.after("=").before(",").toInteger();
             }
            t = t.after(",");
        }
        if (list_exists(nm, type)) {
            syslog(LOG_INFO, "List name %s of this type already defined - ignoring %s", nm.toCharArray(), i->toCharArray() );
            errors = true;
            continue;
        }

        list_info rec;
        rec.type = type;
        rec.name = nm;
        rec.mess_no = m_no;
        if (log_m_no) {
            rec.log_mess_no = log_m_no;
        } else {
            rec.log_mess_no = m_no;
        }

        switch (method_type) {
            case LIST_METHOD_READF_EWS :
                if (readFile(fpath.toCharArray(),&rec.list_ref,false,nm.toCharArray())) {
                    list_vec.push_back( rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
        }
}
}


bool ListMeta::list_exists(String name, int type) {
    if (findList(name, (int)type).name != "" )
        return true;
    else
        return false;
}

ListMeta::list_info ListMeta::findList(String name, int type) {
    list_info t;
    for (std::vector<struct list_info>::iterator i = list_vec.begin(); i != list_vec.end(); i++) {
        if (i->name == name && i->type == type)
            t = *i;
            return t;
    }
    return t;
}

// read in the given file, write the list's ID into the given identifier,
// sort using startsWith or endsWith depending on sortsw, and create a cache file if desired.
// listname is used in error messages.
bool ListMeta::readFile(const char *filename, unsigned int *whichlist, bool sortsw,  const char *listname)
{
    if (strlen(filename) < 3) {
        if (!is_daemonised) {
            std::cerr << "Required Listname " << listname << " is not defined" << std::endl;
        }
        syslog(LOG_ERR, "Required Listname %s is not defined", listname);
        return false;
    }
    int res = o.lm.newItemList(filename, sortsw, 1, true);
    if (res < 0) {
        if (!is_daemonised) {
            std::cerr << "Error opening " << listname << std::endl;
        }
        syslog(LOG_ERR, "Error opening %s", listname);
        return false;
    }
    (*whichlist) = (unsigned)res;
    if (!(*o.lm.l[(*whichlist)]).used) {
        if (sortsw)
            (*o.lm.l[(*whichlist)]).doSort(true);
        else
            (*o.lm.l[(*whichlist)]).doSort(false);
        (*o.lm.l[(*whichlist)]).used = true;
    }
#ifdef DGDEBUG
    std::cout << "Blanket flags are **:*ip:**s:**sip = " << (*o.lm.l[(*whichlist)]).blanketblock << ":" << (*o.lm.l[(*whichlist)]).blanket_ip_block << ":" << (*o.lm.l[(*whichlist)]).blanketsslblock << ":" << (*o.lm.l[(*whichlist)]).blanketssl_ip_block << std::endl;
#endif
    return true;
}
