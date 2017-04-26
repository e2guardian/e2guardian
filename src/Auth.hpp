// AuthPlugin class - interface for plugins for retrieving client usernames
// and filter group membership

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_AUTH
#define __HPP_AUTH

// INCLUDES

#include "Plugin.hpp"
#include "ConfigVar.hpp"
#include "HTTPHeader.hpp"
#include "ListContainer.hpp"

// DEFINES

// success
#define DGAUTH_OK 0

// auth info required for this method not found (continue querying other plugins)
#define DGAUTH_NOMATCH 2

// auth info found, but no such user in filtergroupslist (stop querying plugins - use this code with caution!)
#define DGAUTH_NOUSER 3

// redirect the user to a login page
#define DGAUTH_REDIRECT 4

// auth plugin found a partial or incomplet answer (Eg NTLM): just break ident loop for this request  
#define DGAUTH_NOIDENTPART 5
 
// allow access to http[s] based auth system, but with no persitance
#define DGAUTH_OK_NOPERSIST 9

// any < 0 return code signifies error

// DECLARATIONS

class AuthPlugin : public Plugin
{
    public:
    AuthPlugin(ConfigVar &definition);

    virtual int init(void *args);
    virtual int quit();

    // determine the username
    // return one of these codes:
    // OK - success, username in string
    // REDIRECT - redirect user to URL in string
    // NOMATCH - did not find the necessary info in the request (query remaining plugins)
    // any < 0 - error
    virtual int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user) = 0;

    // determine what filter group the given username is in
    // queries the standard filtergroupslist
    // return one of these codes:
    // OK - success, group no. in fg
    // NOMATCH - did not find a group for this user (query remaining plugins)
    // NOUSER - did not find a group for this user (do not query remaining plugins)
    // any < 0 - error
    virtual int determineGroup(std::string &user, int &fg,ListContainer &uglc);

    // is this a connection-based auth type, i.e. assume all subsequent requests on the pconn are from the same user?
    bool is_connection_based;

    // does this auth type rely on queries from the parent proxy (e.g. NTLM, basic auth)?
    bool needs_proxy_query;
    String getPluginName();
    virtual bool isTransparent()
    {
        return false;
    };
    virtual bool isSSL()
    {
        return false;
    };

    protected:
    ConfigVar cv;

    private:
    String pluginName;
};

// class factory functions for Auth plugins
typedef AuthPlugin *authcreate_t(ConfigVar &);

// Return an instance of the plugin defined in the given configuration file
AuthPlugin *auth_plugin_load(const char *pluginConfigPath);

#endif
