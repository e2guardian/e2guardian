// BearerBasic auth plugin
//
// Plugin for use where e2g is sent auth details in 'bearer' format, but sent in via a Basic header
//
// Token is sent as username and signature as password

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "../Auth.hpp"
#include "../OptionContainer.hpp"
#include "../Logger.hpp"

#include <syslog.h>

extern bool is_daemonised;
extern OptionContainer o;
extern thread_local std::string thread_id;

// DECLARATIONS

// class name is relevant!
class bearer_basic_instance : public AuthPlugin
{
    public:
    bearer_basic_instance(ConfigVar &definition)
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

AuthPlugin *bearer_basic_create(ConfigVar &definition)
{
    return new bearer_basic_instance(definition);
}

// end of Class factory

// proxy auth header username extraction
int bearer_basic_instance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string,
                                    bool &is_real_user, auth_rec &authrec) {
    // don't match for non-basic auth types
    String t(h.getAuthType());
    t.toLower();
    if (t == "basic") {
        // extract token
        string = h.getAuthData();
        if (string.length() > 0) {
            String token, sig;
            token = string;
            sig = token.after(";");
            token = token.before(":");
            token = h.decodeb64(token);
            String tocheck = token;
            tocheck.append(bearer_secret);
            if (tocheck.md5() == sig) {

                authrec.user_name = string;
                authrec.user_source = "bearer_b";
                is_real_user = true;
                return E2AUTH_OK;
            } else {
                DEBUG_auth("signature not valid");
            }
        } else {
            DEBUG_auth("empty authdata");
        }
    } else {
        DEBUG_auth("auth is not Basic or absent");
    }

    return E2AUTH_NOMATCH;
}

int bearer_basic_instance::init(void *args)
{
    bearer_secret = cv["bearersecret"];
    if (bearer_secret.empty()) {
        E2LOGGER_error("No bearersecret supplied in authplugin/BearerBasic.conf");
        return -1;
    }
}

