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
    std::cerr << "REading storyboard file " << filename << std::endl;

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
        std::cerr << "Readline " << linebuffer << std::endl;
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
        if (command == "function") {
            if (in_function) {    // already in another function definition & so assume end of previous function
                curr_function.end();
                // push function to list
                funct_vec.push_back(curr_function);
            }
            in_function = true;
            String temp  = filename;
            curr_function.start(params, ++fnt_cnt, line_no, temp);
            continue;
        }
        if (command == "end") {
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
    std::cerr << "SB read file finished function vect size is "  << funct_vec.size() << "is_top " << is_top << std::endl;

    if (!is_top) return true;

    // only do the 2nd pass once all file(s) have been read
    // in top file now do second pass to record action functions ids in command lines and add list_ids
    std::cerr << "SB Start 2nd pass checking"  << std::endl;

    for (std::vector<SBFunction>::iterator i = funct_vec.begin(); i != funct_vec.end(); i++) {
        for (std::deque<SBFunction::com_rec>::iterator j = i->comm_dq.begin(); j != i->comm_dq.end(); j++) {
            // check condition
            std::cerr << "Line " << j->file_lineno <<  " state is " << j->state << " actionid " << j->action_id << " listname " << j->list_name << " function " << i->name << " id " << i->fn_id << std::endl;

            if(j->state  < SB_STATE_TOPIN)  {   // is an *in condition and requires a list
                std::deque<int> types;
                switch (j->state) {
                    case SB_STATE_SITEIN:
                        types = { LIST_TYPE_IPSITE,LIST_TYPE_SITE,  LIST_TYPE_REGEXP_BOOL};
                        break;
                    case SB_STATE_URLIN:
                        types = { LIST_TYPE_IPSITE,LIST_TYPE_SITE,  LIST_TYPE_URL, LIST_TYPE_REGEXP_BOOL};
                        break;
                    case SB_STATE_SEARCHIN:
                        types= { LIST_TYPE_SEARCH };
                        break;
                    case SB_STATE_EMBEDDEDIN:
                        types = { LIST_TYPE_IPSITE,LIST_TYPE_SITE,  LIST_TYPE_URL, LIST_TYPE_REGEXP_BOOL};
                        break;
                    case SB_STATE_REFERERIN:
                        types = { LIST_TYPE_IPSITE,LIST_TYPE_SITE,  LIST_TYPE_URL, LIST_TYPE_REGEXP_BOOL};
                        break;
                    case SB_STATE_FULLURLIN:
                        types = {  LIST_TYPE_REGEXP_REP };
                        break;
                    case SB_STATE_HEADERIN:
                        types = {  LIST_TYPE_REGEXP_REP, LIST_TYPE_REGEXP_BOOL };
                        break;
                    case SB_STATE_CLIENTIN:
                        types = {  LIST_TYPE_IP, LIST_TYPE_SITE };
                        break;
                    case SB_STATE_EXTENSIONIN:
                        types = {  LIST_TYPE_FILE_EXT };
                        break;
                    case SB_STATE_MIMEIN:
                        types = {  LIST_TYPE_MIME};
                        break;
                }
                bool found = false;
                for (std::deque<int>::iterator k = types.begin(); k != types.end(); k++) {
                    std::cerr << "SB  list name "  << j->list_name << " checking type  " << *k <<  std::endl;
                    ListMeta::list_info listi = LMeta->findList(j->list_name, *k);
                    std::cerr << "list reference " << listi.list_ref   << " '" << listi.name << "' found for " << j->list_name << std::endl;
                    if (listi.name.length()) {
                        j->list_id_dq.push_back(listi);
                        found = true;
                    }
                }
                if (! found ) {
                    // warning message
                    std::cerr << "StoryBoard error: List not defined " << j->list_name << " at line " << j->file_lineno << " of " << i->file_name << std::endl;
                } else {
                    std::cerr << j->list_name << " matches " << j->list_id_dq.size() << " types" << std::endl;
                }

             }
            // check action
            if ( (j->action_id = getFunctID(j->action_name)) == 0) {
                // warnign message
                std::cerr << "StoryBoard error: Action not defined " << j->action_name << " at line " << j->file_lineno << " of " << i->file_name << std::endl;
            }
            std::cerr << "Line " << j->file_lineno <<  " state is " << j->state << " actionid " << j->action_id << " listname " << j->list_name << std::endl;
        }
    }
    // check for required functions

    return true;
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


bool StoryBoard::runFunct(String &fname, NaughtyFilter &cm) {
    return runFunct(getFunctID(fname),cm);
}

bool StoryBoard::runFunct(unsigned int fID, NaughtyFilter &cm) {
    --fID;
    std::cerr << "fID " << fID << " funct_vec size " << funct_vec.size() <<   std::endl;
    SBFunction* F = &(funct_vec[fID]);
    bool action_return = false;

    for (std::deque<SBFunction::com_rec>::iterator i = F->comm_dq.begin(); i != F->comm_dq.end(); i++) {
        bool isListCheck = false;
        bool state_result = false;
        String target;
        String target2;
        String targetful;

            switch (i->state) {
                case SB_STATE_SITEIN:
                    isListCheck = true;
                    target = cm.urldomain;
                    target2 = target;
                    break;
                case SB_STATE_URLIN:
                    isListCheck = true;
                    target = cm.baseurl;
                    target2 = cm.urldomain;
                    targetful = cm.url;
                    break;
                case SB_STATE_FULLURLIN:
                    isListCheck = true;
                    target = cm.baseurl;
                    target2 = cm.urldomain;
                    targetful = cm.url;
                    break;
                case SB_STATE_MIMEIN:
                    isListCheck = true;
                    target = cm.response_header->getContentType();
                    break;
                case SB_STATE_EXTENSIONIN:
                    isListCheck = true;
                    target = cm.response_header->disposition();
                    break;
                case SB_STATE_SEARCHIN:
                    isListCheck = true;
                    target = cm.request_header->searchwords();
                    break;
                case SB_STATE_EMBEDDEDIN:
                    isListCheck = true;
                    // multi targets - maybe we need a target deque???
                    break;
                case SB_STATE_REFERERIN:
                    isListCheck = true;
                    target = cm.request_header->getReferer();   // needs spliting before??
                    target2 = target.getHostname();
                    break;
                case SB_STATE_CONNECT:
                    state_result = cm.isconnect;
                    break;
                case SB_STATE_EXCEPTIONSET:
                    state_result = cm.isexception;
                    break;
                case SB_STATE_GREYSET:
                    state_result = cm.isGrey;
                    break;
                case SB_STATE_BLOCKSET:
                    state_result = cm.isBlocked;
                    break;
                case SB_STATE_MITMSET:
                    state_result = cm.ismitm;
                    break;
                case SB_STATE_DONESET:
                    state_result = cm.isdone;
                    break;
                case SB_STATE_RETURNSET:
                    state_result = cm.isReturn;
                    break;
                case SB_STATE_TRUE:
                    state_result = true;
                    break;
            }
            std::cerr << "SB target" << target << " target2 " << target2 <<   " state_result " << state_result <<
                      " list_check " << isListCheck << std::endl;
        switch (i->state) {
            case SB_STATE_SITEIN:
                isListCheck = true;
                target = cm.urldomain;
                target2 = target;
                break;
            case SB_STATE_URLIN:
                isListCheck = true;
                target = cm.baseurl;
                target2 = cm.urldomain;
                targetful = cm.url;
                break;
            case SB_STATE_FULLURLIN:
                isListCheck = true;
                target = cm.baseurl;
                target2 = cm.urldomain;
                targetful = cm.url;
                break;
            case SB_STATE_SEARCHIN:
                if (cm.isSearch) {
                    isListCheck = true;
                    target = cm.search_words;
                    }
                break;
            case SB_STATE_EMBEDDEDIN:
                isListCheck = true;
                // multi targets - maybe we need a target deque???
                break;
            case SB_STATE_REFERERIN:
                isListCheck = true;
                target = cm.request_header->getReferer();   // needs spliting before??
                target2 = target.getHostname();
                break;
            case SB_STATE_CLIENTIN:
                isListCheck = true;
                target = cm.clientip;
                target2 = cm.clienthost;
                break;
            case SB_STATE_CONNECT:
                state_result = cm.isconnect;
                break;
            case SB_STATE_EXCEPTIONSET:
                state_result = cm.isexception;
                break;
            case SB_STATE_GREYSET:
                state_result = cm.isGrey;
                break;
            case SB_STATE_BLOCKSET:
                state_result = cm.isBlocked;
                break;
            case SB_STATE_MITMSET:
                state_result = cm.ismitm;
                break;
            case SB_STATE_DONESET:
                state_result = cm.isdone;
                break;
            case SB_STATE_RETURNSET:
                state_result = cm.isReturn;
                break;
            case SB_STATE_TRUE:
                state_result = true;
                break;
        }
        std::cerr << "SB target" << target << " target2 " << target2 <<   " state_result " << state_result <<
                                                                                                           " list_check " << isListCheck << std::endl;

        if (isListCheck) {
            for (std::deque<ListMeta::list_info>::iterator j = i->list_id_dq.begin(); j != i->list_id_dq.end(); j++) {
               ListMeta::list_result res;
                String t;
                if ((j->type >= LIST_TYPE_SITE) && (j->type < LIST_TYPE_URL)) {
                    t = target2;
                } else if ( j->type == LIST_TYPE_REGEXP_BOOL || j->type == LIST_TYPE_REGEXP_REP){
                    t = targetful;
                } else {
                    t = target;
                }
                std::cerr << "checking " << j->name << " type " << j->type << std::endl;
               if ( LMeta->inList(*j,t,res)) {  //found
                state_result = true;
                   if (i->isif) {
                       cm.lastcategory = res.category;
                       cm.whatIsNaughtyCategories = res.category;
                       cm.message_no = res.mess_no;
                       cm.log_message_no = res.log_mess_no;
                       cm.lastmatch = res.match;
                       cm.result = res.result;
                   }
                   std::cerr << "SB lc" << cm.lastcategory << " mess_no " << cm.message_no <<   " log_mess " << cm.log_message_no << " match " << res.match << std::endl;
                   break;
                    }


            }
        }
        if (!i->isif)  {
            state_result = !state_result;
        }
        if (!state_result)
            continue;        // nothing to do so continue to next SB line

        action_return = true;

        if  (i->mess_no > 0)  cm.message_no = i->mess_no;
        if  (i->log_mess_no > 0)  cm.log_message_no = i->log_mess_no;

        std::cerr << "lc" << cm.lastcategory << " mess_no " << cm.message_no <<   " log_mess " << cm.log_message_no << " match " << cm.whatIsNaughty << " actionis " << i->action_id << std::endl;

        if (i->action_id > SB_BI_FUNC_BASE) {     // is built-in action
            switch (i->action_id) {
                case SB_FUNC_SETEXCEPTION:
                    cm.isexception = true;
                    //cm.exceptionreason = o.language_list.getTranslation(cm.message_no);
                    cm.whatIsNaughty = o.language_list.getTranslation(cm.message_no) + cm.lastmatch;
                    if (cm.log_message_no == 0)
                        cm.whatIsNaughtyLog = cm.whatIsNaughty;
                    else
                        cm.whatIsNaughtyLog = o.language_list.getTranslation(cm.log_message_no) + cm.lastmatch;
                    cm.exceptioncat  = cm.lastcategory;
                    break;
                case SB_FUNC_SETGREY:
                    cm.isGrey = true;
                    break;
                case SB_FUNC_SETBLOCK:
                    cm.isBlocked = true;
                    cm.whatIsNaughty = o.language_list.getTranslation(cm.message_no) + cm.lastmatch;
                    if (cm.log_message_no == 0)
                        cm.whatIsNaughtyLog = cm.whatIsNaughty;
                    else
                        cm.whatIsNaughtyLog = o.language_list.getTranslation(cm.log_message_no) + cm.lastmatch;
                    cm.whatIsNaughtyCategories = cm.lastcategory;
                    break;
                case SB_FUNC_SETMODURL:
                    cm.urlmodified = true;
                    cm.request_header->setURL(cm.result);
                    cm.url = cm.result;
                    cm.baseurl = cm.url;
                    cm.baseurl.removeWhiteSpace();
                    cm.baseurl.toLower();
                    cm.baseurl.removePTP();
                    cm.logurl = cm.request_header->getLogUrl(false, cm.ismitm);
                    cm.urld = cm.request_header->decode(cm.url);
                    cm.urldomain = cm.url.getHostname();
                    cm.urldomain.toLower();
                std::cerr << "SB URL modified to " << cm.url << std::endl;
                    break;
                case SB_FUNC_SETLOGCAT:
                    cm.logcategory = true;
                    cm.whatIsNaughty = o.language_list.getTranslation(cm.message_no) + cm.lastmatch;
                    if (cm.log_message_no == 0)
                        cm.whatIsNaughtyLog = cm.whatIsNaughty;
                    else
                        cm.whatIsNaughtyLog = o.language_list.getTranslation(cm.log_message_no) + cm.lastmatch;
                    cm.whatIsNaughtyCategories = cm.lastcategory;
                    break;

                    break;
                case SB_FUNC_SETREDIRECT:
                    if (cm.result.size() > 0) {
                        cm.request_header->redirect = cm.result;
                        cm.urlredirect = true;
                    } else {
                        action_return = false;
                    }
                    break;
                case SB_FUNC_SETGOMITM:
                    cm.gomitm = true;
                    break;
                case SB_FUNC_SETADDHEADER:
                    cm.headeradded = true;
                    cm.request_header->addHeader(cm.result);
                    break;
                case SB_FUNC_SETNOCHECKCERT:
                    cm.nocheckcert = true;
                    break;
                case SB_FUNC_SETSEARCHTERM:
                    if (cm.result.size() > 0) {
                        cm.isSearch = true;
                        cm.search_words = cm.result.sort_search();
                        cm.search_terms = cm.result;
                        cm.search_terms.swapChar('+', ' ');
                    };
                    break;
                case SB_FUNC_SETDONE:
                    cm.isdone = true;
                    break;
                case SB_FUNC_SETTRUE:
                    break;
                case SB_FUNC_SETFALSE:
                    action_return = false;
                    break;
            }
        } else {      // is SB defined function
            if (i->action_id > 0) {
                action_return = runFunct(i->action_id,cm);
            }

        }
        if ( i->return_after_action)
            break;
        if (i->return_after_action_is_true && action_return)
            break;
    }

    return action_return;
}

bool StoryBoard::setEntry1( String fname) {
    entry1 = getFunctID(fname);
    if (entry1 > 0) {
        return true;
    }
    return false;
};

bool StoryBoard::setEntry2( String fname) {
    entry2 = getFunctID(fname);
    if (entry2 > 0) {
        return true;
    }
    return false;
}

bool StoryBoard::runFunctEntry1(NaughtyFilter &cm) {
    if (entry1 > 0 )
        return runFunct(entry1, cm);
    else
        return false;
};

bool StoryBoard::runFunctEntry2(NaughtyFilter &cm) {
    if (entry2 > 0 )
        return runFunct(entry2, cm);
    else
        return false;
};
