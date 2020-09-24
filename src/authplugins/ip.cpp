// IP (range, subnet) auth plugin

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

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

// structs linking subnets and IP ranges to filter groups
//struct subnetstruct
// uint32_t maskedaddr;
    //uint32_t mask;
    //int group;
//};

//struct rangestruct {
//    uint32_t startaddr;
//    uint32_t endaddr;
//    int group;
//};

// class for linking IPs to filter groups, complete with comparison operators
// allowing standard C++ sort to work
#ifdef NODEF
class ip
{
    public:
    ip(uint32_t a, int g)
    {
        addr = a;
        group = g;
    };
    uint32_t addr;
    int group;
    int operator<(const ip &a) const
    {
        return addr < a.addr;
    };
    int operator<(const uint32_t &a) const
    {
        return addr < a;
    };
    int operator==(const uint32_t &a) const
    {
        return a == addr;
    };
};
#endif

// class name is relevant!
class ipinstance : public AuthPlugin
{
    public:
    // keep credentials for the whole of a connection - IP isn't going to change.
    // not quite true - what about downstream proxy with x-forwarded-for?
    ipinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        if (!o.use_xforwardedfor)
            is_connection_based = true;
        client_ip_based = true;
    };

    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec,NaughtyFilter &cm);
    //int determineGroup(std::string &user, int &fg, ListContainer &uglc);

    int init(void *args);
    int quit();

    private:
    //std::vector<ip> iplist;
    std::list<subnetstruct> ipsubnetlist;
    std::list<rangestruct> iprangelist;

    int readIPMelangeList(const char *filename);
    int searchList(int a, int s, const uint32_t &ip);
    int inList(const uint32_t &ip);
    int inSubnet(const uint32_t &ip);
    int inRange(const uint32_t &ip);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *ipcreate(ConfigVar &definition)
{
    return new ipinstance(definition);
}

// end of Class factory

//
//
// Standard plugin funcs
//
//

// plugin quit - clear IP, subnet & range lists
int ipinstance::quit()
{
    //iplist.clear();
    //ipsubnetlist.clear();
    //iprangelist.clear();
    return 0;
}

// plugin init - read in ip melange list
int ipinstance::init(void *args)
{
    OptionContainer::SB_entry_map sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_IP;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
	    read_def_fg();
        return 0;
    } else {
        E2LOGGER_error("No story_function defined in IP auth plugin config");
        return -1;
    }
}

// IP-based filter group determination
// never actually return NOUSER from this, because we don't actually look in the filtergroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int ipinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec,NaughtyFilter &cm)
{
    // we don't get usernames out of this plugin, just a filter group
    // for now, use the IP as the username
    bool use_xforwardedfor;
    use_xforwardedfor = false;
    if (o.use_xforwardedfor == 1) {
        if (o.net.xforwardedfor_filter_ip.size() > 0) {
            const char *ip = peercon.getPeerIP().c_str();
            for (unsigned int i = 0; i < o.net.xforwardedfor_filter_ip.size(); i++) {
                if (strcmp(ip, o.net.xforwardedfor_filter_ip[i].c_str()) == 0) {
                    use_xforwardedfor = true;
                    break;
                }
            }
        } else {
            use_xforwardedfor = true;
        }
    }
    if (use_xforwardedfor == 1) {
        // grab the X-Forwarded-For IP if available
        string = h.getXForwardedForIP();
        // or try the client IP from the header
        if (string.length() == 0)
            string = h.getClientIP();
        // otherwise, grab the IP directly from the client connection
        if (string.length() == 0)
        	string = peercon.getPeerIP();
    } else {
        string = h.getClientIP();
        // otherwise, grab the IP directly from the client connection
        if (string.length() == 0)
    	    string = peercon.getPeerIP();
    }
    authrec.user_name = string;
    authrec.user_source = "ip";;
    is_real_user = false;
    return E2AUTH_OK;
}

#ifdef NODEF
int ipinstance::determineGroup(std::string &user, int &rfg, ListContainer &uglc)
{
    struct in_addr sin;
    inet_aton(user.c_str(), &sin);
    uint32_t addr = ntohl(sin.s_addr);
    int fg;
    // check straight IPs, subnets, and ranges
//    fg = inList(addr);
    if (fg >= 0) {
        rfg = fg;
        DEBUG_auth("Matched IP ", user, " to straight IP list");
        return E2AUTH_OK;
    }
//    fg = inSubnet(addr);
    if (fg >= 0) {
        rfg = fg;
        DEBUG_auth("Matched IP ", user, " to subnet");
        return E2AUTH_OK;
    }
//    fg = inRange(addr);
    if (fg >= 0) {
        rfg = fg;
        DEBUG_auth("Matched IP ", user, " to range");
        return E2AUTH_OK;
    }
    DEBUG_auth("Matched IP ", user, " to nothing");
    return E2AUTH_NOMATCH;
}

#endif


