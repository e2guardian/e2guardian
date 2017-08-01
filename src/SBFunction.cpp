// SBFunction - container for StoryBoard function

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
#include "SBFunction.hpp"
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
SBFunction::SBFunction()
{
#ifdef NOT_DEF
    bi_funct_map = {
            "setexception",
            "setgrey",
            "setblock",
            "setmodurl",
            "setdone",
            "true",
            "false",
            "setgomitm",
            "setlogcategory",
            "setaddheader",
            "setredirect",
            "setnocheckcert",
            "setsearchterm"
    };
#endif
}

// delete the memory block when the class is destryed
SBFunction::~SBFunction()
{
    reset();
}

//  clear & reset all values
void SBFunction::reset() {
   // for (std::vector<struct list_info>::iterator i = list_vec.begin(); i != list_vec.end(); i++) {
   //     o.lm.deRefList(i->list_ref);
    //    i->comp.clear();
     //   i->reg_list_ref.clear();
    //}
}

bool SBFunction::start(String & sname, unsigned int id, unsigned int& line_no, String filename) {
    name = sname;
    fn_id = id;
    file_lineno = line_no;
    file_name = filename;
    comm_dq.clear();
    return true;
}

bool SBFunction::end() {
    return true;
}

bool SBFunction::addline(String command, String params, String action, unsigned int line_no) {
    com_rec rec;
    if (command == "if") {
        rec.action_id = SB_COM_IF;
        rec.isif = true;
    } else if (command == "ifnot") {
        rec.action_id = SB_COM_IFNOT;
        rec.isif = false;
    } else {
        std::cout << "StoryBoard error: Invalid command " << command << "at line " << line_no << " of " << file_name << std::endl;
        return false;
    }
    rec.file_lineno = line_no;
    // process params
    std::cerr << "CLine " << params << " Action " << action << std::endl;
    String state;
    String temp;
    String temp2;
    if (params.contains(",")) {
        state = params.before(",");
        std::cerr << "CLine state is " << state << std::endl;
        temp = params.after(",");
    } else {
        state = params;
    }
    state.removeWhiteSpace();
    rec.state = getStateID(state);
    if (rec.state == 0) {
        std::cout << "StoryBoard error: Invalid state" << state << "at line " << line_no << " of " << file_name << std::endl;
        return false;
    }

    if ( temp.length() ) {
        if (temp.contains(",")) {
            temp2 = temp.before(",");
            temp = temp.after(",");
        } else {
            temp2 = temp;
            temp = "";
        }
        temp2.removeWhiteSpace();
        rec.list_name = temp2;
            std::cerr << "CLine list is " << temp2 << std::endl;
     }
    if ( temp.length() ) {
        if (temp.contains(",")) {
            temp2 = temp.before(",");
            temp = temp.after(",");
        } else {
            temp2 = temp;
            temp = "";
        }
        temp2.removeWhiteSpace();
        rec.mess_no = temp2.toInteger();
        std::cerr << "CLine mno is " << temp2 << std::endl;
    }
    if ( temp.length() ) {
        if (temp.contains(",")) {
            temp2 = temp.before(",");
            temp = temp.after(",");
        } else {
            temp2 = temp;
            temp = "";
        }
        temp2.removeWhiteSpace();
        rec.log_mess_no = temp2.toInteger();
        std::cerr << "CLine logmno is " << temp2 << std::endl;
    }
    if ( temp.length() ) {
        if (temp.contains(",")) {
            temp2 = temp.before(",");
            temp = temp.after(",");
        } else {
            temp2 = temp;
            temp = "";
        }
        temp2.removeWhiteSpace();
        if (temp2 == "optional")
            rec.optional = true;
        std::cerr << "CLine optional is true" << std::endl;
    }
    // check list and get list_ID - needs ListMeta object - done in StoryBook::readfile

    rec.return_after_action = false;
    rec.return_after_action_is_true = false;

    if (action.startsWith("return ")) {
        rec.return_after_action = true;
        action = action.after("return ");
    } else if (action.startsWith("returnif ")) {
                rec.return_after_action_is_true = true;
                action = action.after("returnif ");
    };

    action.removeWhiteSpace();

    rec.action_name = action;   // will check this and get action_id later as function may not yet be defined.
    comm_dq.push_back(rec);
    return true;
}

unsigned int SBFunction::getStateID(String & state) {
    unsigned int i = 0;
    while (i < SB_STATE_MAP_SIZE) {
        if ( state == state_map[i]) {
            return ++i;
        }
        ++i;
    }
    return 0;
}

unsigned int SBFunction::getBIFunctID(String &action)  {
    unsigned int i = 0;
//    std::cerr << "getBIFuctID looking for " << action << " in map_size " << bi_funct_map.size() << std::endl;
    while (i < SB_FUNC_MAP_SIZE) {
  //      std::cerr << "getBIFuctID checking index " << i << " " << bi_funct_map.at(i) << std::endl;
        if ( action == bi_funct_map.at(i)) {
    //        std::cerr << "getBIFuctID l;ooking for " << action << std::endl;
            return ++i + SB_BI_FUNC_BASE;
        }
        ++i;
    }
    return 0;
}

String SBFunction::getState(unsigned int id) {
    if (--id < SB_STATE_MAP_SIZE)
        return state_map[id];
    return "";
};

String SBFunction::getBIFunct(unsigned int &id) {
    if (id > 5000) {
        unsigned int i = id - 5001;
        if (i < SB_FUNC_MAP_SIZE)
            return bi_funct_map[i];
    }
    return "";
};

String SBFunction::getName() {
    return name;
}
