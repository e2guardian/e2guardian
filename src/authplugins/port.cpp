// listening PORT auth plugin

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
#include "e2config.h"
#endif

#include "../Auth.hpp"
#include "../RegExp.hpp"
#include "../OptionContainer.hpp"
#include "../Logger.hpp"

#include <algorithm>
#include <unistd.h>
#include <iostream>
#include <fstream>

// GLOBALS

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
    // not quite true - what about downstream proxy with x-forwarded-for?
    portinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        is_connection_based = true;
        client_ip_based = false;
    }

    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec,NaughtyFilter &cm);
    //int determineGroup(std::string &user, int &fg, ListContainer &uglc);

    int init(void *args);
    int quit();

    private:
    std::deque<portstruct> ipportlist;

    int readIPMelangeList(const char *filename);
    int searchList(int a, int s, const unsigned int &ip);
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
    OptionContainer::SB_entry_map sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_PORT;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
	    read_def_fg();
        return 0;
    } else {
        E2LOGGER_error("No story_function defined in port auth plugin config");
        return -1;
    }
}

// Port-based filter group determination
// never actually return NOUSER from this, because we don't actually look in the portgroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int portinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec,NaughtyFilter &cm)
{
    // we don't get usernames out of this plugin, just a filter group
    // for now, use the dest Port as the username
    String s(peercon.getPort());
    string = s;
    authrec.user_name = string;
    authrec.user_source = "port";
    is_real_user = false;
    return E2AUTH_OK;
}

