// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "OptionContainer.hpp"
#include "FOptionContainer.hpp"

#include <iostream>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <algorithm>
#include <memory>
#include <list>
#include <vector>
#include <syslog.h>

// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;

// INPLEMENTATION

// clear out the list
void IPList::reset()
{
    iplist.clear();
    iprangelist.clear();
    ipsubnetlist.clear();
    hostlist.clear();
}

// search for IP in list of individual IPs, ranges, subnets and - if reverse lookups are enabled - hostnames.
bool IPList::inList(const std::string &ipstr, std::string *&host) const
{
    struct in_addr addr;
    inet_aton(ipstr.c_str(), &addr);
    uint32_t ip = ntohl(addr.s_addr);
    // start with individual IPs
    if (std::binary_search(iplist.begin(), iplist.end(), ip)) {
        // only return a hostname if that's what we matched against
        delete host;
        host = NULL;
        return true;
    }

    // ranges
    for (std::list<ipl_rangestruct>::const_iterator i = iprangelist.begin(); i != iprangelist.end(); ++i) {
        if ((ip >= i->startaddr) && (ip <= i->endaddr)) {
            delete host;
            host = NULL;
            return true;
        }
    }

    // subnets
    for (std::list<ipl_subnetstruct>::const_iterator i = ipsubnetlist.begin(); i != ipsubnetlist.end(); ++i) {
        if (i->maskedaddr == (ip & i->mask)) {
            delete host;
            host = NULL;
            return true;
        }
    }

    // hostnames
    // TODO - take in a suggested hostname, look up only if not supplied, and return suggestion if found
    if (o.reverse_client_ip_lookups) {
        std::unique_ptr<std::deque<String> > hostnames;
        if (host == NULL)
            hostnames.reset(ipToHostname(ipstr.c_str()));
        else {
            hostnames.reset(new std::deque<String>);
            hostnames->push_back(*host);
        }
        for (std::deque<String>::iterator i = hostnames->begin(); i != hostnames->end(); ++i) {
            if (std::binary_search(hostlist.begin(), hostlist.end(), *i)) {
                delete host;
                host = new std::string(i->toCharArray());
                return true;
            }
        }
        // Even if we don't match anything, return a hostname
        // if desired for logging and we don't already have one.
        if (o.log_client_hostnames && (host == NULL) && (hostnames->size() > 0))
            host = new std::string(hostnames->front().toCharArray());
    }

    return false;
}

bool IPList::ifsreadIPMelangeList(std::ifstream *input, bool checkendstring, const char *endstring)
{
    // compile regexps for determining whether a list entry is an IP, a subnet (IP + mask), or a range
    RegExp matchIP, matchSubnet, matchRange, matchCIDR;
#ifdef HAVE_PCRE
    matchIP.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    matchSubnet.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
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
    char buffer[2048];
    while (input) {
        if (!input->getline(buffer, sizeof(buffer))) {
            break;
        }
        line = buffer;
        if (checkendstring && line.startsWith(endstring)) {
            break;
        }

        // ignore comments
        if (buffer[0] == '#')
            continue;
        // ignore blank lines
        if (strlen(buffer) < 7)
            continue;
#ifdef DGDEBUG
        std::cout << "line: " << line << std::endl;
#endif
        // store the IP address (numerically, not as a string) and filter group in either the IP list, subnet list or range list
        if (matchIP.match(line.toCharArray(),Rre)) {
            struct in_addr address;
            if (inet_aton(line.toCharArray(), &address)) {
                uint32_t addr = ntohl(address.s_addr);
                iplist.push_back(addr);
            }
        } else if (matchSubnet.match(line.toCharArray(),Rre)) {
            struct in_addr address;
            struct in_addr addressmask;
            String subnet(line.before("/"));
            String mask(line.after("/"));
            if (inet_aton(subnet.toCharArray(), &address) && inet_aton(mask.toCharArray(), &addressmask)) {
                ipl_subnetstruct s;
                uint32_t addr = ntohl(address.s_addr);
                s.mask = ntohl(addressmask.s_addr);
                // pre-mask the address for quick comparison
                s.maskedaddr = addr & s.mask;
                ipsubnetlist.push_back(s);
            }
        } else if (matchCIDR.match(line.toCharArray(),Rre)) {
            struct in_addr address;
            struct in_addr addressmask;
            String subnet(line.before("/"));
            String cidr(line.after("/"));
            int m = cidr.toInteger();
            int host_part = 32 - m;
            if (host_part > -1) {
                String mask = (0xFFFFFFFF << host_part);
                if (inet_aton(subnet.toCharArray(), &address) && inet_aton(mask.toCharArray(), &addressmask)) {
                    ipl_subnetstruct s;
                    uint32_t addr = ntohl(address.s_addr);
                    s.mask = ntohl(addressmask.s_addr);
                    // pre-mask the address for quick comparison
                    s.maskedaddr = addr & s.mask;
                    ipsubnetlist.push_back(s);
                }
            }
        } else if (matchRange.match(line.toCharArray(),Rre)) {
            struct in_addr addressstart;
            struct in_addr addressend;
            String start(line.before("-"));
            String end(line.after("-"));
            if (inet_aton(start.toCharArray(), &addressstart) && inet_aton(end.toCharArray(), &addressend)) {
                ipl_rangestruct r;
                r.startaddr = ntohl(addressstart.s_addr);
                r.endaddr = ntohl(addressend.s_addr);
                iprangelist.push_back(r);
            }
        }
        // hmmm. the line didn't match any of our regular expressions.
        // assume it's a hostname.
        else {
            line.toLower();
            hostlist.push_back(line);
        }
    }
#ifdef DGDEBUG
    std::cout << "starting sort" << std::endl;
#endif
    std::sort(iplist.begin(), iplist.end());
    std::sort(hostlist.begin(), hostlist.end());
#ifdef DGDEBUG
    std::cout << "sort complete" << std::endl;
    std::cout << "ip list dump:" << std::endl;
    std::vector<uint32_t>::iterator i = iplist.begin();
    while (i != iplist.end()) {
        std::cout << "IP: " << *i << std::endl;
        ++i;
    }
    std::cout << "subnet list dump:" << std::endl;
    std::list<ipl_subnetstruct>::iterator j = ipsubnetlist.begin();
    while (j != ipsubnetlist.end()) {
        std::cout << "Masked IP: " << j->maskedaddr << " Mask: " << j->mask << std::endl;
        ++j;
    }
    std::cout << "range list dump:" << std::endl;
    std::list<ipl_rangestruct>::iterator k = iprangelist.begin();
    while (k != iprangelist.end()) {
        std::cout << "Start IP: " << k->startaddr << " End IP: " << k->endaddr << std::endl;
        ++k;
    }
    std::cout << "host list dump:" << std::endl;
    std::vector<String>::iterator l = hostlist.begin();
    while (l != hostlist.end()) {
        std::cout << "Hostname: " << *l << std::endl;
        ++l;
    }
#endif
    return true;
}

// read in a list linking IPs, subnets & IP ranges to filter groups
bool IPList::readIPMelangeList(const char *filename)
{
    // load in the list file
    std::ifstream input(filename);
    if (!input) {
        if (!is_daemonised) {
            std::cerr << "Error reading file (does it exist?): " << filename << std::endl;
        }
        syslog(LOG_ERR, "%s%s", "Error reading file (does it exist?): ", filename);
        return false;
    }
#ifdef DGDEBUG
    std::cout << "reading: " << filename << std::endl;
#endif
    if (ifsreadIPMelangeList(&input, false, NULL)) {
        input.close();
        return true;
    }
    input.close();
    return false;
}
