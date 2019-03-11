// AuthPlugin class - interface for plugins for retrieving client usernames
// and filter group membership

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "Auth.hpp"
#include "OptionContainer.hpp"
#include "LOptionContainer.hpp"

#include <iostream>
#include <syslog.h>

// GLOBALS

extern OptionContainer o;
extern thread_local std::string thread_id;
extern bool is_daemonised;

extern authcreate_t proxycreate;
extern authcreate_t digestcreate;
extern authcreate_t identcreate;
extern authcreate_t ipcreate;
extern authcreate_t portcreate;
extern authcreate_t headercreate;

#ifdef PRT_DNSAUTH
extern authcreate_t dnsauthcreate;
#endif

#ifdef ENABLE_NTLM
extern authcreate_t ntlmcreate;
#endif

// IMPLEMENTATION

AuthPlugin::AuthPlugin(ConfigVar &definition)
    : is_connection_based(false), needs_proxy_query(false)
{
    cv = definition;
    pluginName = cv["plugname"];
}

int AuthPlugin::init(void *args)
{
    return 0;
}

int AuthPlugin::quit()
{
    return 0;
}

String AuthPlugin::getPluginName()
{
    return pluginName;
}

// determine what filter group the given username is in
// return -1 when user not found
int AuthPlugin::determineGroup(std::string &user, int &fg, ListContainer & uglc)
{
    if (user.length() < 1 || user == "-") {
        return DGAUTH_NOMATCH;
    }
    String u(user);
    String lastcategory;
    u.toLower(); // since the filtergroupslist is read in in lowercase, we should do this.
    user = u.toCharArray(); // also pass back to ConnectionHandler, so appears lowercase in logs
    String ue(u);
    ue += "=";

    //char *i = ldl->filter_groups_list.findStartsWithPartial(ue.toCharArray(), lastcategory);
    char *i = uglc.findStartsWithPartial(ue.toCharArray(), lastcategory);

    if (i == NULL) {
#ifdef DGDEBUG
        std::cerr << "User not in filter groups list: " << ue << std::endl;
#endif
        return DGAUTH_NOUSER;
    }
#ifdef DGDEBUG
    std::cerr << "User found: " << i << std::endl;
#endif
    ue = i;
    if (ue.before("=") == u) {
        ue = ue.after("=filter");
        int l = ue.length();
        if (l < 1 || l > 2) {
            return DGAUTH_NOUSER;
        }
        int t;
        t = ue.toInteger();
        if (t > o.numfg) {
            return DGAUTH_NOUSER;
        }
        if (t > 0) {
            fg = --t;
            return DGAUTH_OK;
        }
    }
    return DGAUTH_NOUSER;
}

// take in a configuration file, find the AuthPlugin class associated with the plugname variable, and return an instance
AuthPlugin *auth_plugin_load(const char *pluginConfigPath)
{
    ConfigVar cv;

    if (cv.readVar(pluginConfigPath, "=") > 0) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Unable to load plugin config: " << pluginConfigPath << std::endl;
        }
        syslog(LOG_ERR, "%sUnable to load plugin config %s", thread_id.c_str(), pluginConfigPath);
        return NULL;
    }

    String plugname(cv["plugname"]);
    if (plugname.length() < 1) {
        if (!is_daemonised) {
            std::cerr << thread_id << "Unable read plugin config plugname variable: " << pluginConfigPath << std::endl;
        }
        syslog(LOG_ERR, "%sUnable read plugin config plugname variable %s", thread_id.c_str(), pluginConfigPath);
        return NULL;
    }

    if (plugname == "proxy-basic") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling proxy-basic auth plugin" << std::endl;
#endif
        return proxycreate(cv);
    }

    if (plugname == "proxy-digest") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling proxy-digest auth plugin" << std::endl;
#endif
        return digestcreate(cv);
    }

    if (plugname == "ident") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling ident server auth plugin" << std::endl;
#endif
        return identcreate(cv);
    }

    if (plugname == "ip") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling IP-based auth plugin" << std::endl;
#endif
        return ipcreate(cv);
    }

    if (plugname == "port") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling port-based auth plugin" << std::endl;
#endif
        return portcreate(cv);
    }

    if (plugname == "proxy-header") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling proxy-header auth plugin" << std::endl;
#endif
        return headercreate(cv);
    }

#ifdef PRT_DNSAUTH
    if (plugname == "dnsauth") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling DNS-based auth plugin" << std::endl;
#endif
        return dnsauthcreate(cv);
    }
#endif

#ifdef ENABLE_NTLM
    if (plugname == "proxy-ntlm") {
#ifdef DGDEBUG
        std::cerr << thread_id << "Enabling proxy-NTLM auth plugin" << std::endl;
#endif
        return ntlmcreate(cv);
    }
#endif


    if (!is_daemonised) {
        std::cerr << thread_id << "Unable to load plugin: " << pluginConfigPath << std::endl;
    }
    syslog(LOG_ERR, "%sUnable to load plugin %s", thread_id.c_str(), pluginConfigPath);
    return NULL;
}
