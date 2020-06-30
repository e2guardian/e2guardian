// AuthPlugin class - interface for plugins for retrieving client usernames
// and filter group membership

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "Auth.hpp"
#include "OptionContainer.hpp"
#include "LOptionContainer.hpp"
#include "Logger.hpp"

#include <iostream>

// GLOBALS

extern OptionContainer o;

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
    read_def_fg();
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
int AuthPlugin::determineGroup(std::string &user, int &fg, StoryBoard & story, NaughtyFilter &cm )
{
    if (user.length() < 1 || user == "-") {
        return E2AUTH_NOMATCH;
    }
    String u(user);
    String lastcategory;
    u.toLower(); // since the filtergroupslist is read in in lowercase, we should do this.
    user = u.toCharArray(); // also pass back to ConnectionHandler, so appears lowercase in logs
  //  String ue(u);
  //  ue += "=";

    //char *i = ldl->filter_groups_list.findStartsWithPartial(ue.toCharArray(), lastcategory);
 //   char *i = uglc.findStartsWithPartial(ue.toCharArray(), lastcategory);
    cm.user = user;
    if (!story.runFunctEntry(story_entry,cm)) {
        int t = get_default(!cm.request_header->isProxyRequest);
        if (t > 0) {
            fg = --t;
            cm.authrec->group_source = "pdef";
            return E2AUTH_OK;
        }
        logger_debug("User not in filter groups list for: ", pluginName);
        return E2AUTH_NOGROUP;
      }

    logger_debug("Group found for: ", user, " in ", pluginName);
    fg = cm.filtergroup;
    return E2AUTH_OK;
}

// take in a configuration file, find the AuthPlugin class associated with the plugname variable, and return an instance
AuthPlugin *auth_plugin_load(const char *pluginConfigPath)
{
    ConfigVar cv;

    if (cv.readVar(pluginConfigPath, "=") > 0) {
        logger_error("Unable to load plugin config: ", pluginConfigPath);
        return NULL;
    }

    String plugname(cv["plugname"]);
    if (plugname.length() < 1) {        
        logger_error("Unable read plugin config plugname variable: ", pluginConfigPath);
        return NULL;
    }

    if (plugname == "proxy-basic") {
        logger_debug("Enabling proxy-basic auth plugin");
        return proxycreate(cv);
    }

    if (plugname == "proxy-digest") {
        logger_debug("Enabling proxy-digest auth plugin");
        return digestcreate(cv);
    }

    if (plugname == "ident") {
        logger_debug("Enabling ident server auth plugin");
        return identcreate(cv);
    }

    if (plugname == "ip") {
        logger_debug("Enabling IP-based auth plugin");
        return ipcreate(cv);
    }

    if (plugname == "port") {
        logger_debug("Enabling port-based auth plugin");
        return portcreate(cv);
    }

    if (plugname == "proxy-header") {
        logger_debug("Enabling proxy-header auth plugin");
        return headercreate(cv);
    }

#ifdef PRT_DNSAUTH
    if (plugname == "dnsauth") {
        logger_debug("Enabling DNS-based auth plugin");
        return dnsauthcreate(cv);
    }
#endif

#ifdef ENABLE_NTLM
    if (plugname == "proxy-ntlm") {
        logger_debug("Enabling proxy-NTLM auth plugin");
        return ntlmcreate(cv);
    }
#endif

    logger_error("Unable to load plugin: ", pluginConfigPath);
    return NULL;
}

int AuthPlugin::get_default(bool is_transparent) {
    if (is_transparent && tran_default_fg > 0) {
       // syslog(LOG_ERR, "%spa default set as %d", thread_id.c_str(), tran_default_fg);
        return tran_default_fg;
    }
    else if (default_fg > 0) {
        //syslog(LOG_ERR, "%spa default set as %d", thread_id.c_str(), default_fg);
        return default_fg;
    }
    return 0;
}

void AuthPlugin::read_def_fg() {
    String t = cv["defaultfiltergroup"];
    int i = t.toInteger();
    if(i > 0 && i <= o.filter_groups) {
        default_fg = i;
    }
    t = cv["defaulttransparentfiltergroup"];
    i = t.toInteger();
    if(i > 0 && i <= o.filter_groups) {
        tran_default_fg = i;
    }
}
