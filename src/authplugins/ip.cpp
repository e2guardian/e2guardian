// IP (range, subnet) auth plugin

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


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

// structs linking subnets and IP ranges to filter groups
struct subnetstruct {
	uint32_t maskedaddr;
	uint32_t mask;
	int group;
};

struct rangestruct {
	uint32_t startaddr;
	uint32_t endaddr;
	int group;
};

// class for linking IPs to filter groups, complete with comparison operators
// allowing standard C++ sort to work
class ip {
public:
	ip(uint32_t a, int g) {
		addr = a;
		group = g;
	};
	uint32_t addr;
	int group;
	int operator < (const ip &a) const {
		return addr < a.addr;
	};
	int operator < (const uint32_t &a) const {
		return addr < a;
	};
	int operator == (const uint32_t &a) const {
		return a == addr;
	};
};

// class name is relevant!
class ipinstance:public AuthPlugin
{
public:
	// keep credentials for the whole of a connection - IP isn't going to change.
	// not quite true - what about downstream proxy with x-forwarded-for?
	ipinstance(ConfigVar &definition):AuthPlugin(definition)
	{
		if (!o.use_xforwardedfor)
			is_connection_based = true;
	};

	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
	int determineGroup(std::string &user, int &fg);

	int init(void* args);
	int quit();
private:
	std::vector<ip> iplist;
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

AuthPlugin *ipcreate(ConfigVar & definition)
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
int ipinstance::quit() {
	iplist.clear();
	ipsubnetlist.clear();
	iprangelist.clear();
	return 0;
}

// plugin init - read in ip melange list
int ipinstance::init(void* args) {
	String fname(cv["ipgroups"]);
	if (fname.length() > 0) {
		return readIPMelangeList(fname.toCharArray());
	} else {
		if (!is_daemonised)
			std::cerr << "No ipgroups file defined in IP auth plugin config" << std::endl;
		syslog(LOG_ERR, "No ipgroups file defined in IP auth plugin config");
		return -1;
	}
}

// IP-based filter group determination
// never actually return NOUSER from this, because we don't actually look in the filtergroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int ipinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
	// we don't get usernames out of this plugin, just a filter group
	// for now, use the IP as the username
	
	if (o.use_xforwardedfor) {
		// grab the X-Forwarded-For IP if available
		string = h.getXForwardedForIP();
		// otherwise, grab the IP directly from the client connection
		if (string.length() == 0)
			string = peercon.getPeerIP();
	} else {
		string = peercon.getPeerIP();
	}
	return DGAUTH_OK;
}

int ipinstance::determineGroup(std::string &user, int &fg)
{
	struct in_addr sin;
	inet_aton(user.c_str(), &sin);
	uint32_t addr = ntohl(sin.s_addr);
	// check straight IPs, subnets, and ranges
	fg = inList(addr);
	if (fg >= 0) {
#ifdef DGDEBUG
		std::cout << "Matched IP " << user << " to straight IP list" << std::endl;
#endif
		return DGAUTH_OK;
	}
	fg = inSubnet(addr);
	if (fg >= 0) {
#ifdef DGDEBUG
		std::cout << "Matched IP " << user << " to subnet" << std::endl;
#endif
		return DGAUTH_OK;
	}
	fg = inRange(addr);
	if (fg >= 0) {
#ifdef DGDEBUG
		std::cout << "Matched IP " << user << " to range" << std::endl;
#endif
		return DGAUTH_OK;
	}
#ifdef DGDEBUG
	std::cout << "Matched IP " << user << " to nothing" << std::endl;
#endif
	return DGAUTH_NOMATCH;
}

//
//
// IP list functions (straight match, range match, subnet match)
//
//

// search for IP in list & return filter group on success, -1 on failure
int ipinstance::inList(const uint32_t &ip) {
	if (iplist.size() > 0) {
		return searchList(0, iplist.size(), ip);
	}
	return -1;
}

// binary search list for given IP & return filter group, or -1 on failure
int ipinstance::searchList(int a, int s, const uint32_t &ip) {
	if (a > s) return -1;
	int m = (a + s) / 2;
	if (iplist[m] == ip) return iplist[m].group;
	if (iplist[m] < ip) return searchList(m + 1, s, ip);
	if (a == s) return -1;
	return searchList(a, m - 1, ip);
}

// search subnet list for given IP & return filter group or -1
int ipinstance::inSubnet(const uint32_t &ip) {
	for(std::list<subnetstruct>::const_iterator i = ipsubnetlist.begin(); i != ipsubnetlist.end(); ++i) {
		if (i->maskedaddr == (ip & i->mask)) {
			return i->group;
		}
	}
	return -1;
}

// search range list for a range containing given IP & return filter group or -1
int ipinstance::inRange(const uint32_t &ip) {
	for(std::list<rangestruct>::const_iterator i = iprangelist.begin(); i != iprangelist.end(); ++i) {
		if ((ip >= i->startaddr) && (ip <= i->endaddr)) {
			return i->group;
		}
	}
	return -1;
}

// read in a list linking IPs, subnets & IP ranges to filter groups
// return 0 for success, -1 for failure, 1 for warning
int ipinstance::readIPMelangeList(const char *filename) {
	// load in the list file
	std::ifstream input ( filename );
	if (!input) {
		if (!is_daemonised) {
			std::cerr << "Error reading file (does it exist?): " << filename << std::endl;
		}
		syslog(LOG_ERR, "%s%s","Error reading file (does it exist?): ",filename);
		return -1;
	}

	// compile regexps for determining whether a list entry is an IP, a subnet (IP + mask), or a range
	RegExp matchIP, matchSubnet, matchRange;
#ifdef HAVE_PCRE
	matchIP.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
	matchSubnet.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
	matchRange.comp("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}-\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
#else
	matchIP.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
	matchSubnet.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
	matchRange.comp("^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}-[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$");
#endif

	// read in the file
	String line;
	String key, value;
	char buffer[ 2048 ];
	bool warn = false;
	while (input) {
		if (!input.getline(buffer, sizeof( buffer ))) {
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
		}
		else {
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
		// store the IP address (numerically, not as a string) and filter group in either the IP list, subnet list or range list
		if (matchIP.match(key.toCharArray())) {
			struct in_addr address;
			if (inet_aton(key.toCharArray(), &address)) {
				iplist.push_back(ip(ntohl(address.s_addr),value.toInteger()-1));
			}
		}
		else if (matchSubnet.match(key.toCharArray())) {
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
				s.group = value.toInteger()-1;
				ipsubnetlist.push_back(s);
			}
		}
		else if (matchRange.match(key.toCharArray())) {
			struct in_addr addressstart;
			struct in_addr addressend;
			String start(key.before("-"));
			String end(key.after("-"));
			if (inet_aton(start.toCharArray(), &addressstart) && inet_aton(end.toCharArray(), &addressend)) {
				rangestruct r;
				r.startaddr = ntohl(addressstart.s_addr);
				r.endaddr = ntohl(addressend.s_addr);
				r.group = value.toInteger()-1;
				iprangelist.push_back(r);
			}
		}
		// hmmm. the key didn't match any of our regular expressions. output message & return a warning value.
		else {
			if (!is_daemonised)
				std::cerr << "Entry " << line << " in " << filename << " was not recognised as an IP address, subnet or range" << std::endl;
			syslog(LOG_ERR, "Entry %s in %s was not recognised as an IP address, subnet or range", line.toCharArray(), filename);
			warn = true;
		}
	}
	input.close();
#ifdef DGDEBUG
	std::cout << "starting sort" << std::endl;
#endif
	std::sort(iplist.begin(), iplist.end());
#ifdef DGDEBUG
	std::cout << "sort complete" << std::endl;
	std::cout << "ip list dump:" << std::endl;
	std::vector<ip>::const_iterator i = iplist.begin();
	while (i != iplist.end()) {
		std::cout << "IP: " << i->addr << " Group: " << i->group << std::endl;
		++i;
	}
	std::cout << "subnet list dump:" << std::endl;
	std::list<subnetstruct>::const_iterator j = ipsubnetlist.begin();
	while (j != ipsubnetlist.end()) {
		std::cout << "Masked IP: " << j->maskedaddr << " Mask: " << j->mask << " Group: " << j->group << std::endl;
		++j;
	}
	std::cout << "range list dump:" << std::endl;
	std::list<rangestruct>::const_iterator k = iprangelist.begin();
	while (k != iprangelist.end()) {
		std::cout << "Start IP: " << k->startaddr << " End IP: " << k->endaddr << " Group: " << k->group << std::endl;
		++k;
	}
#endif
	// return either warning or success
	return warn ? 1 : 0;
}
