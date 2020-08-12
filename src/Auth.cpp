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
extern authcreate_t PF_basic_create;

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
#ifdef E2DEBUG
             std::cerr << "User not in filter groups list for: " << pluginName.c_str() << std::endl;
#endif
             return E2AUTH_NOGROUP;
      }

#ifdef E2DEBUG
    std::cerr << "Group found for: " << user.c_str() << " in " << pluginName.c_str() << std::endl;
#endif
     fg = cm.filtergroup;
     return E2AUTH_OK;
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
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-basic auth plugin" << std::endl;
#endif
        return proxycreate(cv);
    }

    if (plugname == "proxy-digest") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-digest auth plugin" << std::endl;
#endif
        return digestcreate(cv);
    }

    if (plugname == "ident") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling ident server auth plugin" << std::endl;
#endif
        return identcreate(cv);
    }

    if (plugname == "ip") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling IP-based auth plugin" << std::endl;
#endif
        return ipcreate(cv);
    }

    if (plugname == "port") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling port-based auth plugin" << std::endl;
#endif
        return portcreate(cv);
    }

    if (plugname == "proxy-header") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-header auth plugin" << std::endl;
#endif
        return headercreate(cv);
    }

    if (plugname == "pf-basic") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling proxy-header auth plugin" << std::endl;
#endif
        return PF_basic_create(cv);
    }

#ifdef PRT_DNSAUTH
    if (plugname == "dnsauth") {
#ifdef E2DEBUG
        std::cerr << thread_id << "Enabling DNS-based auth plugin" << std::endl;
#endif
        return dnsauthcreate(cv);
    }
#endif

#ifdef ENABLE_NTLM
    if (plugname == "proxy-ntlm") {
#ifdef E2DEBUG
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
   // syslog(LOG_ERR, "%sloading def_fg plugin ....", thread_id.c_str());
    String t = cv["defaultfiltergroup"];
    //syslog(LOG_ERR, "%sdef_fg string is %s", thread_id.c_str(), t.c_str());
    int i = t.toInteger();
    //syslog(LOG_ERR, "%sdef_fg int is %d", thread_id.c_str(), i);
    if(i > 0 && i <= o.filter_groups) {
        default_fg = i;
        //syslog(LOG_ERR, "%sdeffg loaded as %d", thread_id.c_str(), default_fg);
    }
    t = cv["defaulttransparentfiltergroup"];
    i = t.toInteger();
    if(i > 0 && i <= o.filter_groups) {
        tran_default_fg = i;
        //syslog(LOG_ERR, "%strandeffg loaded as %d", thread_id.c_str(), tran_default_fg);
    }
}
