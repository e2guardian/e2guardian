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

    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec);
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
    OptionContainer::auth_entry sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_IP;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
	read_def_fg();
        return 0;
    } else {
        logger_error("No story_function defined in IP auth plugin config");
        return -1;
    }
}

// IP-based filter group determination
// never actually return NOUSER from this, because we don't actually look in the filtergroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int ipinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec)
{
    // we don't get usernames out of this plugin, just a filter group
    // for now, use the IP as the username
    bool use_xforwardedfor;
    use_xforwardedfor = false;
    if (o.use_xforwardedfor == 1) {
        if (o.xforwardedfor_filter_ip.size() > 0) {
            const char *ip = peercon.getPeerIP().c_str();
            for (unsigned int i = 0; i < o.xforwardedfor_filter_ip.size(); i++) {
                if (strcmp(ip, o.xforwardedfor_filter_ip[i].c_str()) == 0) {
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
        logger_debug("Matched IP ", user, " to straight IP list");
        return E2AUTH_OK;
    }
//    fg = inSubnet(addr);
    if (fg >= 0) {
        rfg = fg;
        logger_debug("Matched IP ", user, " to subnet");
        return E2AUTH_OK;
    }
//    fg = inRange(addr);
    if (fg >= 0) {
        rfg = fg;
        logger_debug("Matched IP ", user, " to range");
        return E2AUTH_OK;
    }
    logger_debug("Matched IP ", user, " to nothing");
    return E2AUTH_NOMATCH;
}

#endif

#ifdef NODEF
//
//
// IP list functions (straight match, range match, subnet match)
//
//

// search for IP in list & return filter group on success, -1 on failure
int ipinstance::inList(const uint32_t &ip)
{
    if (iplist.size() > 0) {
        return searchList(0, iplist.size(), ip);
    }
    return -1;
}

// binary search list for given IP & return filter group, or -1 on failure
int ipinstance::searchList(int a, int s, const uint32_t &ip)
{
    if (a > s)
        return -1;
    int m = (a + s) / 2;
    if (iplist[m] == ip)
        return iplist[m].group;
    if (iplist[m] < ip)
        return searchList(m + 1, s, ip);
    if (a == s)
        return -1;
    return searchList(a, m - 1, ip);
}

// search subnet list for given IP & return filter group or -1
int ipinstance::inSubnet(const uint32_t &ip)
{
    for (std::list<subnetstruct>::const_iterator i = ipsubnetlist.begin(); i != ipsubnetlist.end(); ++i) {
        if (i->maskedaddr == (ip & i->mask)) {
            return i->group;
        }
    }
    return -1;
}

// search range list for a range containing given IP & return filter group or -1
int ipinstance::inRange(const uint32_t &ip)
{
    for (std::list<rangestruct>::const_iterator i = iprangelist.begin(); i != iprangelist.end(); ++i) {
        if ((ip >= i->startaddr) && (ip <= i->endaddr)) {
            return i->group;
        }
    }
    return -1;
}
#endif // NODEF

#ifdef NODEF
// read in a list linking IPs, subnets & IP ranges to filter groups
// return 0 for success, -1 for failure, 1 for warning
int ipinstance::readIPMelangeList(const char *filename)
{
    // load in the list file
    std::ifstream input(filename);
    if (!input) {
        logger_error("Error reading file (does it exist?): ", filename);
        return -1;
    }

    // compile regexps for determining whether a list entry is an IP, a subnet (IP + mask), or a range
    RegExp matchIP, matchSubnet, matchRange, matchCIDR;
#ifdef HAVE_PCRE
    matchIP.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    matchSubnet.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    matchCIDR.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,2}$");
    matchRange.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}-\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
#else
    matchIP.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
    matchSubnet.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
    matchCIDR.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}$");
    matchRange.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}-[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
#endif
    RegResult Rre;

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
            logger_error("No filter group given; entry ", line, " in ", filename);
            warn = true;
            continue;
        }
        logger_debug("key: ", key , "value: ", value.toInteger() );

        if ((value.toInteger() < 1) || (value.toInteger() > o.filter_groups)) {
            logger_error("Filter group out of range; entry ", line, " in ", filename);
            warn = true;
            continue;
        }
        // store the IP address (numerically, not as a string) and filter group in either the IP list, subnet list or range list
        if (matchIP.match(key.toCharArray(),Rre)) {
            struct in_addr address;
            if (inet_aton(key.toCharArray(), &address)) {
                iplist.push_back(ip(ntohl(address.s_addr), value.toInteger() - 1));
            }
        } else if (matchSubnet.match(key.toCharArray(),Rre)) {
            struct in_addr address;
            struct in_addr addressmask;
            String subnet(key.before("/"));
            String mask(key.after("/"));
            if (inet_aton(subnet.toCharArray(), &address) && inet_aton(mask.toCharArray(), &addressmask)) {
                subnetstruct s;
                int addr = ntohl(address.s_addr);
                s.mask = ntohl(addressmask.s_addr);
                // pre-mask the address for quick comparison
                s.maskedaddr = addr & s.mask;
                s.group = value.toInteger() - 1;
                ipsubnetlist.push_back(s);
            }
        } else if (matchCIDR.match(key.toCharArray(),Rre)) {
            struct in_addr address;
            struct in_addr addressmask;
            String subnet(key.before("/"));
            String cidr(key.after("/"));
            int m = cidr.toInteger();
            int host_part = 32 - m;
            if (host_part > -1) {
                String mask = (0xFFFFFFFF << host_part);
                if (inet_aton(subnet.toCharArray(), &address) && inet_aton(mask.toCharArray(), &addressmask)) {
                    subnetstruct s;
                    uint32_t addr = ntohl(address.s_addr);
                    s.mask = ntohl(addressmask.s_addr);
                    // pre-mask the address for quick comparison
                    s.maskedaddr = addr & s.mask;
                    s.group = value.toInteger() - 1;
                    ipsubnetlist.push_back(s);
                }
            }
        } else if (matchRange.match(key.toCharArray(),Rre)) {
            struct in_addr addressstart;
            struct in_addr addressend;
            String start(key.before("-"));
            String end(key.after("-"));
            if (inet_aton(start.toCharArray(), &addressstart) && inet_aton(end.toCharArray(), &addressend)) {
                rangestruct r;
                r.startaddr = ntohl(addressstart.s_addr);
                r.endaddr = ntohl(addressend.s_addr);
                r.group = value.toInteger() - 1;
                iprangelist.push_back(r);
            }
        }
        // hmmm. the key didn't match any of our regular expressions. output message & return a warning value.
        else {
            logger_error("Entry ", line, " in ", filename, " was not recognised as an IP address, subnet or range");
            warn = true;
        }
    }
    input.close();
    logger_debug("starting sort");
    std::sort(iplist.begin(), iplist.end());

#ifdef E2DEBUG
    logger_debug("sort complete");
    logger_debug("ip list dump:");
    std::vector<ip>::const_iterator i = iplist.begin();
    while (i != iplist.end()) {
        logger_debug("IP: ", i->addr, " Group: ", i->group );
        ++i;
    }
    logger_debug("subnet list dump:");
    std::list<subnetstruct>::const_iterator j = ipsubnetlist.begin();
    while (j != ipsubnetlist.end()) {
        logger_debug("Masked IP: ", j->maskedaddr, " Mask: ", j->mask, " Group: ", j->group );
        ++j;
    }
    logger_debug("range list dump:");
    std::list<rangestruct>::const_iterator k = iprangelist.begin();
    while (k != iprangelist.end()) {
        logger_debug("Start IP: ", k->startaddr, " End IP: ", k->endaddr, " Group: ", k->group );
        ++k;
    }
#endif
    // return either warning or success
    return warn ? 1 : 0;
}
#endif // NODEF
