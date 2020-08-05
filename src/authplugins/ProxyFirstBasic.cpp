// ProxyFirstBasic auth plugin
//
// Plugin for use where e2g is behind squid and squid sends user in basic 
// format

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "../Auth.hpp"
#include "../OptionContainer.hpp"

#include <syslog.h>

extern bool is_daemonised;
extern OptionContainer o;
extern thread_local std::string thread_id;

// DECLARATIONS

// class name is relevant!
class pf_basic_instance : public AuthPlugin
{
    public:
    pf_basic_instance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        needs_proxy_query = false;
        client_ip_based = false;
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec);
    int init(void *args);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *PF_basic_create(ConfigVar &definition)
{
    return new pf_basic_instance(definition);
}

// end of Class factory

// proxy auth header username extraction
int pf_basic_instance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec)
{
    // don't match for non-basic auth types
    String t(h.getAuthType());
    t.toLower();
    if (t != "basic")
        return E2AUTH_NOMATCH;
    // extract username
    string = h.getAuthData();
    if (string.length() > 0) {
        string.resize(string.find_first_of(':'));
        authrec.user_name = string;
        authrec.user_source = "pf_basic";
	is_real_user = true;
        return E2AUTH_OK;
    }
    return E2AUTH_NOMATCH;
}

int pf_basic_instance::init(void *args)
{
    OptionContainer::auth_entry sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_PF_BASIC;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
        read_def_fg();
        return 0;
    } else {
        if (!is_daemonised)
            std::cerr << thread_id << "No story_function defined in proxy auth plugin config" << std::endl;
        syslog(LOG_ERR, "No story_function defined in proxy auth plugin config");
        return -1;
    }
}

