// Proxy auth plugin

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif

#include "../Auth.hpp"

#include <syslog.h>

// DECLARATIONS

// class name is relevant!
class proxyinstance : public AuthPlugin
{
    public:
    proxyinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        needs_proxy_query = true;
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *proxycreate(ConfigVar &definition)
{
    return new proxyinstance(definition);
}

// end of Class factory

// proxy auth header username extraction
int proxyinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user)
{
    // don't match for non-basic auth types
    String t(h.getAuthType());
    t.toLower();
    if (t != "basic")
        return DGAUTH_NOMATCH;
    // extract username
    string = h.getAuthData();
    if (string.length() > 0) {
        string.resize(string.find_first_of(':'));
        return DGAUTH_OK;
    }
    return DGAUTH_NOMATCH;
}
