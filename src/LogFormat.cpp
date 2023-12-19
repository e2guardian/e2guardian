

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include "LogFormat.hpp"
#include "OptionContainer.hpp"

extern OptionContainer o;


int LogFormat::get_key(String &name) {
    for (int k = 0; k < TOP; k++) {
        if (labels[k] == name)
            return k;
    }
    return -1;
}

int LogFormat::get_format_key(String &name) {
    for (int k = 0; k < LOG_FORMAT_TOP; k++) {
        if (format_labels[k] == name)
            return k;
    }
    return -1;
}

LogFormat::LogFormat() {
    reset();
}

LogFormat::~LogFormat() {
    reset();
}

void LogFormat::reset() {

   // item_list.clear();
   // reqh_needed_list.clear();
   // resh_needed_list.clear();

    for (int i = 0; i < TOP; i++) {
        present[i] = false;
    }

}

bool LogFormat::readfile(String &filename) {

    String line;
    std::string linebuffer;

    std::ifstream ffile(filename, std::ios::in); // e2guardian.conf
    if (!ffile.good()) {
        E2LOGGER_error("error reading log format file: ", filename);
        return false;
    }
    while (!ffile.eof()) {
        std::getline(ffile, linebuffer);
        line = linebuffer.c_str();
        if (line.empty()) continue;
        if (line.startsWith("#")) {
        if (line.startsWith("#format:")) {
            String type = line.after("\"").before("\"");
            int f = get_format_key(type);
            if (f < 0) {
                E2LOGGER_warning("format type ", type, "is not known - setting to default 'tsv");
                f = LOG_FORMAT_TSV;
            }
            format_type = f;
            switch(format_type) {
                case LOG_FORMAT_TSV:
                    delimiter = "\t";
                    break;
                case LOG_FORMAT_CSV:
                    delimiter = ",";
                    break;
                case LOG_FORMAT_SSV:
                    delimiter = " ";
                    break;
            }
            continue;
        } else if(line.startsWith("#add_header:")){
            add_header = true;
            continue;
        } else if(line.startsWith("#add_quotes_to_strings:")){
            add_quotes_to_strings = true;
            continue;
        } else if(line.startsWith("#use_dash_for_blanks:")){
            use_dash_for_blanks = true;
            continue;
        }
        // ok it is just a comment line
            continue;
        }
        // remove any comments in line and any remaining white space
        if (line.contains("#")) {
            line = line.before("#");
            line.removeWhiteSpace();
        }

        logf_item il;

        if(line.contains(".")) {
            il.name = line.before(".");             // store label
            line = line.after(".");     // get rid of label from line
        } else {
            il.name = line;
        }

        bool has_params = false;
        String check_key = line;
        if (check_key.contains(":")) {
            check_key = line.before(":");
            has_params = true;
        } else {
            check_key = line;
        };

        int k = get_key(check_key);


        if (k < 0) {
            E2LOGGER_warning("Log field ", line, " is not known - assuming blank field - from format file ", filename);
            k = BLANK;
        }
        il.code = static_cast<F>(k);
        if (has_params) {
            line = line.after(":");
            il.header_name = line;
            line.toLower();
            if (il.code == REQHEADER){
                DEBUG_trace("pushing to reqh list ",line);
                reqh_needed_list.push_back(line);
            } else if(il.code == RESHEADER) {
                DEBUG_trace("pushing to resh list ",line);
                resh_needed_list.push_back(line);
            } else {
                E2LOGGER_warning("Log field type ", check_key, " does not allow parameters - parameters ignored - from format file ", filename);
            }
        }
        present[il.code] = true;

        // add extra presents for items needed by combi and 'or' codes
        if (il.code == WHAT_COMBI) {
            present[WHATISNAUGHTY] = true;
            present[ACTIONWORD] = true;
        }
        if (il.code == CLIENTHOSTORIP) {
            present[CLIENTIP] = true;
            present[CLIENTHOST] = true;
        }
        if ((il.code == AUTHROUTE) || (il.code == LISTENINGPORT) | (il.code == PROXYSERVICE) ) {
            present[EXTFLAGS] = true;
        }

        item_list.push_back(il);
    };

    if(present[CLIENTHOST]) {
        o.log.log_client_hostnames = true;
        o.conn.reverse_client_ip_lookups = true;
    }
    DEBUG_trace("Type of format_type is ",format_type );
    DEBUG_trace("Size of item_list is ", item_list.size());
    DEBUG_trace("Size of item_list from function list_size() is ", list_size());
    if(item_list.size() == 0) {
        E2LOGGER_error("Log format file ", filename, "has no Log fields defined");
        ffile.close();
        return false;
    };
    ffile.close();
    return true;
}

int LogFormat::list_size() {
    return item_list.size();
}