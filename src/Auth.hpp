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
#include "LOptionContainer.hpp"
#include <deque>

// DEFINES

// success
#define E2AUTH_OK 0

// auth info required for this method not found (continue querying other plugins)
#define E2AUTH_NOMATCH 2

// auth info found, but no such user in filtergroupslist (stop querying plugins - use this code with caution!)
#define E2AUTH_NOUSER 3

// auth info found, but no such user in group for this plugin  stop querying plugins - use this code with caution!)
#define E2AUTH_NOGROUP 3

// redirect the user to a login page
#define E2AUTH_REDIRECT 4

// allow access to http[s] based auth system, but with no persitance
#define E2AUTH_OK_NOPERSIST 9

// auth plugin found a partial or incomplet answer (Eg NTLM): just break ident loop for this request  
#define E2AUTH_NOIDENTPART 5

// identify returns this if it has determined both user and group (and added group id to authrec)
#define E2AUTH_OK_GOT_GROUP 10

// This means plugin has sent 407 to client, so no further processing of this request
#define E2AUTH_407_SENT    11

// identify returns this if it has determined both user and group (and added group name to authrec)
#define E2AUTH_OK_GOT_GROUP_NAME 12

// any < 0 return code signifies error

// auth_rec structure for use by storyboarding/extended logging
struct auth_rec {
    String user_name;
    bool is_authed;
    int filter_group;
    String fg_name;
    bool is_proxy = false;
    bool is_transparent = false;
    bool is_icap = false;
    bool is_tlsproxy = false;
    String user_source;
    String group_source;
};

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
    virtual int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec,NaughtyFilter &cm) = 0;

    // determine what filter group the given username is in
    // queries the standard filtergroupslist
    // return one of these codes:
    // OK - success, group no. in fg
    // NOMATCH - did not find a group for this user (query remaining plugins)
    // NOUSER - did not find a group for this user (do not query remaining plugins)
    // any < 0 - error
    virtual int determineGroup(std::string &user, int &fg,StoryBoard &story,NaughtyFilter &cm);

    // is this a connection-based auth type, i.e. assume all subsequent requests on the pconn are from the same user?
    bool is_connection_based;

    std::deque<int> portlist;   // holds list of ports this plugin is valid for
    void read_ports();
    bool port_matched(int &port);


    int default_fg = 0;
    int tran_default_fg = 0;
    int get_default(bool is_transparent);

    void read_def_fg();

    bool client_ip_based;

    int story_entry = 0;

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
    String bearer_secret;
    String bearer_realm;

    private:
    String pluginName;
};

// class factory functions for Auth plugins
typedef AuthPlugin *authcreate_t(ConfigVar &);

// Return an instance of the plugin defined in the given configuration file
AuthPlugin *auth_plugin_load(const char *pluginConfigPath);

#endif
