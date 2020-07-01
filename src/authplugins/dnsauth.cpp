// DNS auth plugin


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

#include <sys/types.h>
#include <algorithm>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>

// GLOBALS

extern OptionContainer o;
extern int h_errno;

// DECLARATIONS

// user record struct
struct userstruct {
    String ippath;
    String user;
    int group;
};

String basedomain;

String authurl;

String authprefix;

bool redirect_to_auth;

// class name is relevant!
class dnsauthinstance : public AuthPlugin
{
    public:
    // keep credentials for the whole of a connection - IP isn't going to change.
    // not quite true - what about downstream proxy with x-forwarded-for?
    dnsauthinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        client_ip_based = true;
        if (!o.use_xforwardedfor)
            is_connection_based = true;
    };

    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec);
    int determineGroup(std::string &user, int &fg, ListContainer &uglc);

    int init(void *args);
    int quit();

    private:
    userstruct userst;
    bool getdnstxt(String &ippath);
    String dns_error(int herror);
    bool inAuthByPassLists(HTTPHeader &h);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *dnsauthcreate(ConfigVar &definition)
{
    return new dnsauthinstance(definition);
}

// end of Class factory

//

// Standard plugin funcs
//
//

// plugin quit - clear IP, subnet & range lists
int dnsauthinstance::quit()
{
    return 0;
}

// plugin init - read in vars
int dnsauthinstance::init(void *args)
{
    basedomain = cv["basedomain"];
    authurl = cv["authurl"];
    authprefix = cv["prefix_auth"];
    String t;
    t = cv["redirect_to_auth"];
    if ((t.length() < 1) || (t == "yes")) {
        redirect_to_auth = true;
    } else {
        redirect_to_auth = false;
    };
    if (basedomain.length() < 1) {
        logger_error("No basedomain defined in DNS auth plugin config");
        return -1;
    }
    if (authurl.length() < 1) {
        logger_error("No authurl defined in DNS auth plugin config");
        return -1;
    }
    if (authprefix.length() < 1) {
        logger_error("No prefix_auth defined in DNS auth plugin config");
        return -1;
    }

    logger_debug( "basedomain is ", basedomain, " authurl is ", authurl);
    return 0;
}

// DNS-AUTH filter group determination
// never actually return NOUSER from this, because we don't actually look in the filtergroupslist.
// NOUSER stops ConnectionHandler from querying subsequent plugins.
int dnsauthinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, /*int &fg,*/ std::string &string, bool &is_real_user,auth_rec &authrec)
{
    String p1, p2, ippath;

    p1 = peercon.getPeerIP();

    if (o.use_xforwardedfor) {
        // grab the X-Forwarded-For IP if available
        p2 = h.getXForwardedForIP();
        if (p2.length() > 0) {
            ippath = p1 + "-" + p2;
        } else {
            ippath = p1;
        }
    } else {
        ippath = p1;
    }

    logger_debug("IPPath is ", ippath);

    // change '.' to '-'
    ippath.swapChar('.', '-');
    logger_debug("IPPath is ", ippath);
    if (getdnstxt(ippath)) {
        string = userst.user;
        is_real_user = true;
        authrec.user_name = string;
        authrec.user_source = "dnsa";
        return E2AUTH_OK;
    } else {
        // redirect code
        if (redirect_to_auth) { // used to force log-in
            // dnsauth plug-in must be last
            // check if this is request to authurl or in authexception lists
            if (h.url().startsWith(authprefix) || inAuthByPassLists(h)) {
                string = "::auth::";
                userst.user = string;
                userst.group = 0;
                return E2AUTH_OK_NOPERSIST;
            } else {
                string = authurl + "=" + h.URLEncode();
                return E2AUTH_REDIRECT;
            }
        } else {
            return E2AUTH_NOMATCH; // used for log-in on demand
            // needs dnsauth plug-in to be first
        }
    }
}

int dnsauthinstance::determineGroup(std::string &user, int &fg, ListContainer &uglc)
{
    fg = userst.group;
    logger_debug("Matched user", user, " to group ", fg, " in cached DNS record");
    return E2AUTH_OK;
}

bool dnsauthinstance::getdnstxt(String &ippath)
{
    // get info from DNS
    union {
        HEADER hdr;
        u_char buf[NS_PACKETSZ];
    } response;
    int responseLen;

    ns_msg handle; /* handle for response message */
    responseLen = res_querydomain(ippath.c_str(), basedomain.c_str(), ns_c_in, ns_t_txt, (u_char *)&response, sizeof(response));
    if (responseLen < 0) {
        logger_debug("DNS query returned error ", dns_error(h_errno));
        return false;
    }
    if (ns_initparse(response.buf, responseLen, &handle) < 0) {
        logger_debug("ns_initparse returned error ", strerror(errno));
        return false;
    }

    //int rrnum; /* resource record number */
    ns_rr rr; /* expanded resource record */
    //u_char *cp;
    //char ans[MAXDNAME];

    int i = ns_msg_count(handle, ns_s_an);
    if (i > 0) {
        if (ns_parserr(&handle, ns_s_an, 0, &rr)) {
            logger_debug("ns_paserr returned error ", strerror(errno));
            return false;
        } else {
            if (ns_rr_type(rr) == ns_t_txt) {
                logger_debug("ns_rr_rdlen returned ", ns_rr_rdlen(rr));
                u_char *k = (u_char *)ns_rr_rdata(rr);
                char p[400];
                unsigned int j = 0;
                for (unsigned int j1 = 1; j1 < ns_rr_rdlen(rr); j1++) {
                    p[j++] = k[j1];
                }
                p[j] = '\0';
                logger_debug("ns_rr_data returned ", p);
                String dnstxt(p);
                userst.user = dnstxt.before(",");
                userst.group = (dnstxt.after(",")).toInteger() - 1;
                return true;
            }
        }
    }
    return true;
}

String dnsauthinstance::dns_error(int herror)
{

    String s;

    switch (herror) {
    case HOST_NOT_FOUND:
        s = "HOST_NOT_FOUND";
        break;
    case TRY_AGAIN:
        s = "TRY_AGAIN - DNS server failure";
        break;
    case NO_DATA:
        s = "NO_DATA - unexpected DNS error";
        break;
    default:
        String S2(herror);
        s = "DNS - Unexpected error number " + S2;
        break;
    }
    return s;
}

bool dnsauthinstance::inAuthByPassLists(HTTPHeader &h)
{
    String url = h.url();
    String urld = h.decode(url);
    //FOptionContainer* foc = o.currentLists()->fg[0];
    url.removePTP();
    if (url.contains("/")) {
        url = url.before("/");
    }

    // Find other way to do this using Storyboarding

   // bool is_ip = (*foc).isIPHostname(url);
//    bool is_ssl = h.requestType() == "CONNECT";

 //   if ((*foc).inAuthExceptionSiteList(urld, true, is_ip, is_ssl)) {
  //      //						exceptioncat = (*o.lm.l[(*o.fg[filtergroup]).exception_site_list]).lastcategory.toCharArray();
   //     return true;
    //} else if ((*foc).inAuthExceptionURLList(urld, true, is_ip, is_ssl)) {
     //   //					exceptioncat = (*o.lm.l[(*o.fg[filtergroup]).exception_url_list]).lastcategory.toCharArray();
      //  return true;
    //}
    return false;
}
