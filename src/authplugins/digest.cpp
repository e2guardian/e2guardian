// Digest auth plugin
// Based on contribution by Darryl Sutherland <darryl@weblink.co.za>

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#include "../Auth.hpp"
#include "../OptionContainer.hpp"

#include <syslog.h>

extern bool is_daemonised;
extern OptionContainer o;
extern thread_local std::string thread_id;

// DECLARATIONS

// class name is relevant!
class digestinstance : public AuthPlugin
{
    public:
    digestinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        needs_proxy_query = true;
        client_ip_based = false;
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec);
    int init(void *args);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *digestcreate(ConfigVar &definition)
{
    return new digestinstance(definition);
}

// end of Class factory

// proxy auth header username extraction
int digestinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec)
{
    // don't match for non-digest auth types
    String t = h.getAuthType();
    t.toLower();
    if (t != "digest")
        return DGAUTH_NOMATCH;
    // extract username
    string = h.getRawAuthData();
    if (string.length() > 0) {
        String temp(string);
        temp = temp.after("username=\"");
        temp = temp.before("\"");
        string = temp;
        authrec.user_name = string;
        authrec.user_source = "digest";
	is_real_user = true;
        return DGAUTH_OK;
    }
    return DGAUTH_NOMATCH;
}

int digestinstance::init(void *args)
{
    OptionContainer::auth_entry sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_DIGEST_PROXY;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
	read_def_fg();
        return 0;
    } else {
        if (!is_daemonised)
            std::cerr << thread_id << "No story_function defined in digest auth plugin config" << std::endl;
        syslog(LOG_ERR, "No story_function defined in digest auth plugin config");
        return -1;
    }
}
