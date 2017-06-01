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
#include "StoryBoard.hpp"
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
StoryBoard::StoryBoard()
{
    fnt_cnt = 0;
}

// delete the memory block when the class is destryed
StoryBoard::~StoryBoard()
{
    reset();
}

//  clear & reset all values
void StoryBoard::reset() {
   // for (std::vector<struct list_info>::iterator i = list_vec.begin(); i != list_vec.end(); i++) {
   //     o.lm.deRefList(i->list_ref);
    //    i->comp.clear();
     //   i->reg_list_ref.clear();
    //}
}

#ifdef NOTDEF
bool StoryBoard::load_type(int type, std::deque<String> &list) {
    unsigned int method_type =0;
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
            // PhraseList types to be added
                }
    std::cerr << "reading deque" << std::endl;
    bool errors = false;
    int dq_size = list.size();
    for (int i = dq_size -1; i > -1; i--) { // search backward thru list
        // parse line
        String t;
        t = list[i];
        std::cerr << "reading %s" << t.toCharArray() << std::endl;
        String nm, fpath;
        unsigned int m_no, log_m_no=0;
        t.removeWhiteSpace();
        t = t + ",";
        while (t.length() > 0) {
            if (t.startsWith("name=")) {
                nm = t.after("=").before(",");
            } else if (t.startsWith("messageno=")) {
                m_no = t.after("=").before(",").toInteger();
            } else if (t.startsWith("logmessageno=")) {
            log_m_no = t.after("=").before(",").toInteger();
            } else if (t.startsWith("path=")) {
                fpath = t.after("=").before(",");
             }
            t = t.after(",");
        }
        if (list_exists(nm, type)) {
            syslog(LOG_INFO, "List name %s of this type already defined - ignoring %s", nm.toCharArray(), t.toCharArray() );
            errors = true;
            continue;
        }

        list_info rec;
        rec.type = type;
        rec.method_type = method_type;
        rec.name = nm;
        rec.mess_no = m_no;
        if (log_m_no) {
            rec.log_mess_no = log_m_no;
        } else {
            rec.log_mess_no = m_no;
        }
        std::cerr << "name = " << nm.toCharArray() << " m_no=" << (int)m_no << "log_m_no="
                                             << rec.log_mess_no << " path=" << fpath.toCharArray() << std::endl ;

        switch (method_type) {
            case LIST_METHOD_READF_EWS :
                if (readFile(fpath.toCharArray(),&rec.list_ref,false,nm.toCharArray())) {
                    list_vec.push_back( rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_READF_SWS :
                if (readFile(fpath.toCharArray(),&rec.list_ref,true,nm.toCharArray())) {
                    list_vec.push_back( rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
            case LIST_METHOD_REGEXP_BOOL :
                if (readRegExMatchFile(fpath.toCharArray(), nm.toCharArray(),rec.list_ref,rec.comp,rec.source,rec.reg_list_ref)) {
                    list_vec.push_back( rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
            case LIST_METHOD_REGEXP_REPL :
               if (readRegExReplacementFile(fpath.toCharArray(), nm.toCharArray(),rec.list_ref,rec.replace,rec.comp)) {
                    list_vec.push_back( rec);
                } else {
                    syslog(LOG_ERR, "Unable to read %s", fpath.toCharArray());
                    errors = true;
                };
                break;
        }
}
}


bool StoryBoard::list_exists(String name, int type) {
    if (findList(name, (int)type).name != "" )
        return true;
    else
        return false;
}

StoryBoard::list_info StoryBoard::findList(String name, int type) {
    list_info t;
    for (std::vector<struct list_info>::iterator i = list_vec.begin(); i != list_vec.end(); i++) {
        if (i->name == name && i->type == type)
            t = *i;
            return t;
    }
    return t;
}

bool StoryBoard::inList(String name, int type, String &tofind, bool ip, bool ssl, list_result &res) {
    list_info info = findList(name, type);
    if (info.name == "")
        return false;
    char *match;
    switch (type)   {
        case LIST_TYPE_SITE :
            match = inSiteList(tofind,info.list_ref, false, ip, ssl, res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                return true;
            }
            break;
        case LIST_TYPE_URL:
            match = inURLList(tofind,info.list_ref, false, ip, ssl, res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                return true;
            }
            break;
        case LIST_TYPE_SEARCH :
            match = inSearchList(tofind,info.list_ref,  res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                return true;
            }
            break;
        case LIST_TYPE_MIME:
            match = o.lm.l[info.list_ref]->findInList(tofind.toCharArray(),res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
                return true;
            }
            break;
        case LIST_TYPE_FILE_EXT:
            match = o.lm.l[info.list_ref]->findEndsWith(tofind.toCharArray(),res.category);
            if (match == NULL) {
                return false;
            } else {
                res.match = match;
                res.mess_no = info.mess_no;
                res.log_mess_no = info.log_mess_no;
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
                return true;
            }
            return false;
         }
            break;
    }
}
#endif

// read in the given file, write the list's ID into the given identifier,
// sort using startsWith or endsWith depending on sortsw, and create a cache file if desired.
// listname is used in error messages.
bool StoryBoard::readFile(const char *filename, ListMeta & LM, bool is_top) {
    if (strlen(filename) < 3) {
        if (!is_daemonised) {
            std::cerr << "Storyboard file" << filename << " is not defined" << std::endl;
        }
        syslog(LOG_ERR, "Storyboard file %s is not defined", filename);
        return false;
    }
    LMeta = &LM;
    std::string linebuffer; // a string line buffer ;)
    String temp; // a String for temporary manipulation
    String line;
    String command;
    String params;
    String action;
    SBFunction curr_function;
    bool in_function = false;
    size_t len = 0;
    std::ifstream listfile(filename, std::ios::in); // open the file for reading
    if (!listfile.good()) {
        if (!is_daemonised) {
            std::cerr << "Error opening Storyboard file (does it exist?): " << filename << std::endl;
        }
        syslog(LOG_ERR, "Error opening Storyboard file (does it exist?): %s", filename);
        return false;
    }
    bool caseinsensitive = true;
    unsigned int line_no = 0;
    while (!listfile.eof()) { // keep going until end of file
        getline(listfile, linebuffer); // grab a line
        ++line_no;
        if (linebuffer.length() == 0) { // sanity checking
            continue;
        }
        line = linebuffer.c_str();
        line.removeWhiteSpace();
        if (caseinsensitive)
            line.toLower();
        // handle included list files
        if (line.startsWith(".")) {
            temp = line.after(".include<").before(">");
            if (temp.length() > 0) {
                if (!readFile(temp.toCharArray(), *LMeta, false)) {
                    listfile.close();
                    return false;
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }
        if (line.startsWith("#")) continue;   // ignore comment lines
        command = line.before("(");
        command.removeWhiteSpace();
        params = line.before(")").after("(");
        params.removeWhiteSpace();
        action = line.after(")");
        action.removeWhiteSpace();
        if (command == "startfunction") {
            if (in_function) {    // already in another function definition & so assume end of previous function
                curr_function.end();
                // push function to list
                funct_vec.push_back(curr_function);
            }
            in_function = true;
            curr_function.start(params, ++fnt_cnt, line_no);
            continue;
        }
        if (command == "endfunction") {
            if (in_function) {
                curr_function.end();
                // push function to list
                funct_vec.push_back(curr_function);
                in_function = false;
            }    // otherwise ignore
            continue;
        }
         if(! curr_function.addline(command, params, action, line_no))
             return false;
    }

    if(in_function) {  // at eof so now end
        curr_function.end();
        // push function to list
        funct_vec.push_back(curr_function);
    }

    if (!is_top)
         return true;

    // only do the 2nd pass once all file(s) have been read
    // in top file now do second pass to record action functions ids in command lines and add list_ids

    for (std::vector<SBFunction>::iterator i = funct_vec.begin(); i != funct_vec.end(); i++) {
        for (std::deque<SBFunction::com_rec>::iterator j = i->comm_dq.begin(); j != i->comm_dq.end(); j++) {
            // check condition
            if(j->state  < SB_STATE_TOPIN)  {   // is an *in condition and requires a list
                std::deque<int> types;
                switch (j->state) {
                    case SB_STATE_SITEIN:
                        types = { LIST_TYPE_SITE, LIST_TYPE_IP, LIST_TYPE_REGEXP_BOOL};
                        break;
                    case SB_STATE_URLIN:
                        types = { LIST_TYPE_SITE, LIST_TYPE_IP, LIST_TYPE_URL, LIST_TYPE_REGEXP_BOOL};
                        break;
                    case SB_STATE_SEARCHIN:
                        types= { LIST_TYPE_SEARCH };
                        break;
                    case SB_STATE_EMBEDDEDIN:
                        types = { LIST_TYPE_SITE, LIST_TYPE_IP, LIST_TYPE_URL, LIST_TYPE_REGEXP_BOOL};
                        break;
                }
                for (std::deque<int>::iterator k = types.begin(); k != types.end(); k++) {
                    unsigned int lr = LMeta->findList(j->list_name, *k).list_ref;
                    if (lr) j->list_id_dq.push_back(lr);
                }
                if (j->list_id_dq.begin()  == j->list_id_dq.end()) {
                    // warning message
                    std::cout << "StoryBoard error: List not defined" << j->list_name << "at line " << j->file_lineno << " of " << i->file_name << std::endl;
                }

             }
            // check action
            if ( (j->action_id = getFunctID(j->action_name)) == 0) {
                // warnign message
                std::cout << "StoryBoard error: Action not defined" << j->action_name << "at line " << j->file_lineno << " of " << i->file_name << std::endl;
            }
        }
    }
}

unsigned int StoryBoard::getFunctID( String & fname) {
    unsigned int i = 0;
    // check built in functions first
    i = funct_vec[0].getBIFunctID(fname);
    if (i > 0)  return i;
    // check StoryBoard defined functions
    for (std::vector<SBFunction>::iterator j = funct_vec.begin(); j != funct_vec.end(); j++) {
        if (j->name == fname)
            return j->fn_id;
    }
    return 0;
}




