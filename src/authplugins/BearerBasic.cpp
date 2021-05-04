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

class JWT_token {
public:
    // These are all required
    String sub;    // username
    String fgr;     // filter group name
    String aud;     // target e2g server/tenant - may be used for checking, by super-proxy for forwarding destination, or by tenanted e2g to determine tenant.
    long exp = 0;     // expiration timestamp
    // These are optional
    String cip;     // client IP (similar to x-forwarded - may be used by super-proxy)
    String clid;    // client id
    String jti;     // Unique id of token

    bool load(String token,NaughtyFilter &cm) {   // returns true if valid
        String temp = token.after("{");
        int man_cnt = 0;
        while ( !temp.empty() ) {
            String line;
            if (temp.contains(",")) {
                line = temp.before(",");
                temp = temp.after(",");
            } else {
                line = temp.before("}");
                temp = "";
            }

            String key = line.before(":");
            String data = line.after(":");
            key.removeWhiteSpace();
            key.removeChar('"');
            data.removeWhiteSpace();
            data.removeChar('"');
            if (key == "sub") {
                sub = data;
                man_cnt++;
            } else if (key == "fgr") {
                fgr = data;
                man_cnt++;
            } else if (key == "aud") {
                aud = data;
                man_cnt++;
            } else if (key == "exp") {
                man_cnt++;
                exp = data.toLong();
            } else if (key == "cip") {
                cip = data;
            } else if (key == "clid") {
                clid = data;
            } else if (key == "jti") {
                jti = data;
            }
        }
            if (man_cnt < 4) {
                DEBUG_auth("Mandatory token field missing");
                return false;
            }
            if (cm.thestart.tv_sec > exp) {
                DEBUG_auth("Token has expired on:", exp);
                return false;
        }
        return true;
        }

};

// class name is relevant!
class bearer_basic_instance : public AuthPlugin
{
    public:
    bearer_basic_instance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
        client_ip_based = false;
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user, auth_rec &authrec,NaughtyFilter &cm);
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
int bearer_basic_instance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &username,
                                    bool &is_real_user, auth_rec &authrec,NaughtyFilter &cm) {
    // don't match for non-basic auth types
    String t(h.getAuthType());
    t.toLower();
    if (t == "basic") {
        // extract token
        String string;
        string = h.getAuthData();
        //string = h.decodeb64(string);
        DEBUG_auth("decoded auth string:", string);
        DEBUG_auth("decoded auth string length:", string.length());
        if (string.length() > 0) {
            String token, sig;
            token = string;
            sig = token.after(":");
            //sig = h.decodeb64(sig);
            token = token.before(":");
            //token = h.decodeb64(token);
            String tocheck = token;
            tocheck.append(bearer_secret);
            DEBUG_auth("tocheck:", tocheck);
            String gen_md5 = tocheck.md5();
            gen_md5.toLower();
            DEBUG_auth("tocheck.md5:", gen_md5);
            DEBUG_auth("sig sent", sig);
            if (gen_md5 == sig) {
                token += "=";
                token = h.decodeb64(token);
                DEBUG_auth("plain token:", token);
                JWT_token token_struct;
                if(token_struct.load(token,cm)) {

                    authrec.user_name = token_struct.sub;
                    username = token_struct.sub;
                    authrec.fg_name = token_struct.fgr;
                    authrec.user_source = "bearer_b";
                    authrec.group_source = "bearer_b";
                    is_real_user = true;
                    return E2AUTH_OK_GOT_GROUP_NAME;
                }

            } else {
                DEBUG_auth("signature not valid");
            }
        } else {
            DEBUG_auth("empty authdata");
        }
    } else {
        DEBUG_auth("auth is not Basic or absent");
    }

    // need to add logic to send 407 (and close??)
    String outmess = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"";
    outmess += bearer_realm;
    outmess += "\"\r\n\r\n";
    peercon.writeString(outmess);
    return E2AUTH_407_SENT;
}

int bearer_basic_instance::init(void *args)
{
    AuthPlugin::init(args);
    bearer_secret = cv["bearersecret"];
    if (bearer_secret.empty()) {
        E2LOGGER_error("No bearersecret supplied in authplugin/BearerBasic.conf");
        return -1;
    }
    bearer_realm= cv["realm"];
    if (bearer_realm.empty()) {
        E2LOGGER_error("No realm supplied in authplugin/BearerBasic.conf");
        return -1;
    }
    return 0;
}

