// IP (range, port) auth plugin

//Please refer to http://dansguardian.org/?page=copyright2
//for the license for this code.

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#include "../Auth.hpp"
#include "../RegExp.hpp"
#include "../OptionContainer.hpp"

#include <syslog.h>
#include <algorithm>
#include <unistd.h>
#include <iostream>
#include <fstream>

// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;

// DECLARATIONS

// structs linking ports to filter groups
struct portstruct {
    unsigned long int port;
    int group;
};

// class name is relevant!
class portinstance : public AuthPlugin
{
    public:
    // keep credentials for the whole of a connection - IP isn't going to change.
    portinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        is_connection_based = true;
    }

    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user);
    int determineGroup(std::string &user, int &fg, ListContainer &uglc);

    int init(void *args);
    int quit();

    private:
    std::deque<portstruct> ipportlist;

    int readIPMelangeList(const char *filename);
    int searchList(int a, int s, const int &ip);
    int inList(const int &ip);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *portcreate(ConfigVar &definition)
{
    return new portinstance(definition);
}

// end of Class factory

//
//
// Standard plugin funcs
//
//

// plugin quit - clear IP, port & range lists
int portinstance::quit()
{
    ipportlist.clear();
    return 0;
}

// plugin init - read in ip melange list
int portinstance::init(void *args)
{
    String fname(cv["portgroups"]);
    if (fname.length() > 0) {
        return readIPMelangeList(fname.toCharArray());
    } else {
        if (!is_daemonised)
            std::cerr << "No portgroups file defined in port auth plugin config" << std::endl;
        syslog(LOG_ERR, "No portgroups file defined in port auth plugin config");
        return -1;
    }
}

// Port-based filter group determination
// never actually return NOUSER from this, because we don't actually look in the portgroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int portinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, /*int &fg,*/ std::string &string, bool &is_real_user)
{
    // we don't get usernames out of this plugin, just a filter group
    // for now, use the dest Port as the username
    String s(peercon.getPort());
    string = s;

    return DGAUTH_OK;
}

int portinstance::determineGroup(std::string &user, int &fg, ListContainer &uglc)
{
    // check ports
    String s = user;
    fg = inList(s.toInteger());
    if (fg >= 0) {
#ifdef DGDEBUG
        std::cout << "Matched port " << user << " to port list" << std::endl;
#endif
        return DGAUTH_OK;
    }
#ifdef DGDEBUG
    std::cout << "Matched port " << user << " to nothing" << std::endl;
#endif
    return DGAUTH_NOMATCH;
}

//
//
// Port list functions (port match)
//
//

// search for port in list & return filter group on success, -1 on failure
int portinstance::inList(const int &port)
{
    if (ipportlist.size() > 0) {
        return searchList(0, ipportlist.size(), port);
    }
    return -1;
}

// binary search list for given port & return filter group, or -1 on failure
int portinstance::searchList(int a, int s, const int &port)
{
    if (a > s)
        return -1;
    int m = (a + s) / 2;
    if (ipportlist[m].port == port)
        return ipportlist[m].group;
    if (ipportlist[m].port < port)
        return searchList(m + 1, s, port);
    if (a == s)
        return -1;
    return searchList(a, m - 1, port);
}

// read in a list linking ports to filter groups
// return 0 for success, -1 for failure, 1 for warning
int portinstance::readIPMelangeList(const char *filename)
{
    // load in the list file
    std::ifstream input(filename);
    if (!input) {
        if (!is_daemonised) {
            std::cerr << "Error reading file (does it exist?): " << filename << std::endl;
        }
        syslog(LOG_ERR, "%s%s", "Error reading file (does it exist?): ", filename);
        return -1;
    }

    // read in the file
    String line;
    String key, value;
    char buffer[2048];
    bool warn = false;
    while (input) {
        if (!input.getline(buffer, sizeof(buffer))) {
            break;
        }
        // ignore comments
        if (buffer[0] == '#')
            continue;
        // ignore blank lines
        if (strlen(buffer) < 10)
            continue;
        line = buffer;
        // split into key & value
        if (line.contains("=")) {
            key = line.before("=");
            key.removeWhiteSpace();
            value = line.after("filter");
        } else {
            if (!is_daemonised)
                std::cerr << "No filter group given; entry " << line << " in " << filename << std::endl;
            syslog(LOG_ERR, "No filter group given; entry %s in %s", line.toCharArray(), filename);
            warn = true;
            continue;
        }
#ifdef DGDEBUG
        std::cout << "key: " << key << std::endl;
        std::cout << "value: " << value.toInteger() << std::endl;
#endif
        if ((value.toInteger() < 1) || (value.toInteger() > o.filter_groups)) {
            if (!is_daemonised)
                std::cerr << "Filter group out of range; entry " << line << " in " << filename << std::endl;
            syslog(LOG_ERR, "Filter group out of range; entry %s in %s", line.toCharArray(), filename);
            warn = true;
            continue;
        }
        // store the IP port(numerically, not as a string) and filter group in the port list
        if (int p = key.toInteger()) {
            portstruct s;
            s.port = p;
            s.group = value.toInteger() - 1;
            ipportlist.push_back(s);
        }
        // hmmm. the key didn't match any of our regular expressions. output message & return a warning value.
        else {
            if (!is_daemonised)
                std::cerr << "Entry " << line << " in " << filename << " was not recognised as an port " << std::endl;
            syslog(LOG_ERR, "Entry %s in %s was not recognised as an port", line.toCharArray(), filename);
            warn = true;
        }
    }
    input.close();
#ifdef DGDEBUG
    std::cout << "starting sort" << std::endl;
#endif
//	std::sort(ipportlist.begin(), ipportlist.end());
#ifdef DGDEBUG
    std::cout << "sort complete" << std::endl;
    std::cout << "port list dump:" << std::endl;
    std::deque<portstruct>::iterator i = ipportlist.begin();
    while (i != ipportlist.end()) {
        std::cout << "port: " << i->port << " Group: " << i->group << std::endl;
        i++;
    }
#endif
    // return either warning or success
    return warn ? 1 : 0;
}
