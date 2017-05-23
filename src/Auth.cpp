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
        std::cout << "User not in filter groups list: " << ue << std::endl;
#endif
        return DGAUTH_NOUSER;
    }
#ifdef DGDEBUG
    std::cout << "User found: " << i << std::endl;
#endif
    ue = i;
    if (ue.before("=") == u) {
        ue = ue.after("=filter");
        int l = ue.length();
        if (l < 1 || l > 2) {
            return DGAUTH_NOUSER;
        }
        fg = ue.toInteger();
        if (fg > o.numfg) {
            return DGAUTH_NOUSER;
        }
        if (fg > 0) {
            fg--;
        }
        return DGAUTH_OK;
    }
    return DGAUTH_NOUSER;
}

// take in a configuration file, find the AuthPlugin class associated with the plugname variable, and return an instance
AuthPlugin *auth_plugin_load(const char *pluginConfigPath)
{
    ConfigVar cv;

    if (cv.readVar(pluginConfigPath, "=") > 0) {
        if (!is_daemonised) {
            std::cerr << "Unable to load plugin config: " << pluginConfigPath << std::endl;
        }
        syslog(LOG_ERR, "Unable to load plugin config %s", pluginConfigPath);
        return NULL;
    }

    String plugname(cv["plugname"]);
    if (plugname.length() < 1) {
        if (!is_daemonised) {
            std::cerr << "Unable read plugin config plugname variable: " << pluginConfigPath << std::endl;
        }
        syslog(LOG_ERR, "Unable read plugin config plugname variable %s", pluginConfigPath);
        return NULL;
    }

    if (plugname == "proxy-basic") {
#ifdef DGDEBUG
        std::cout << "Enabling proxy-basic auth plugin" << std::endl;
#endif
        return proxycreate(cv);
    }

    if (plugname == "proxy-digest") {
#ifdef DGDEBUG
        std::cout << "Enabling proxy-digest auth plugin" << std::endl;
#endif
        return digestcreate(cv);
    }

    if (plugname == "ident") {
#ifdef DGDEBUG
        std::cout << "Enabling ident server auth plugin" << std::endl;
#endif
        return identcreate(cv);
    }

    if (plugname == "ip") {
#ifdef DGDEBUG
        std::cout << "Enabling IP-based auth plugin" << std::endl;
#endif
        return ipcreate(cv);
    }

    if (plugname == "port") {
#ifdef DGDEBUG
        std::cout << "Enabling port-based auth plugin" << std::endl;
#endif
        return portcreate(cv);
    }

    if (plugname == "proxy-header") {
#ifdef DGDEBUG
        std::cout << "Enabling proxy-header auth plugin" << std::endl;
#endif
        return headercreate(cv);
    }

#ifdef PRT_DNSAUTH
    if (plugname == "dnsauth") {
#ifdef DGDEBUG
        std::cout << "Enabling DNS-based auth plugin" << std::endl;
#endif
        return dnsauthcreate(cv);
    }
#endif

#ifdef ENABLE_NTLM
    if (plugname == "proxy-ntlm") {
#ifdef DGDEBUG
        std::cout << "Enabling proxy-NTLM auth plugin" << std::endl;
#endif
        return ntlmcreate(cv);
    }
#endif


#ifdef __SSLMITM
//	if (plugname == "ssl") {
#ifdef DGDEBUG
//		std::cout << "Enabling SSL login/core auth plugin" << std::endl;
#endif
//		return sslcorecreate(cv);
//	}

//	if (plugname == "core") {
#ifdef DGDEBUG
//		std::cout << "Enabling SSL login/core auth plugin" << std::endl;
#endif
//		return sslcorecreate(cv);
//	}
#endif //__SSLMITM

    if (!is_daemonised) {
        std::cerr << "Unable to load plugin: " << pluginConfigPath << std::endl;
    }
    syslog(LOG_ERR, "Unable to load plugin %s", pluginConfigPath);
    return NULL;
}
