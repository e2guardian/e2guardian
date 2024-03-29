// Ident server auth plugin

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


// GLOBALS

extern OptionContainer o;

// DECLARATIONS

// class name is relevant!
class identinstance : public AuthPlugin
{
    public:
    identinstance(ConfigVar &definition)
        : AuthPlugin(definition){
        client_ip_based = true;    // not sure if this is correct!!
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec,NaughtyFilter &cm);
    int init(void *args);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *identcreate(ConfigVar &definition)
{
    return new identinstance(definition);
}

// end of Class factory

// ident server username extraction
// checkme: needs better error reporting
int identinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec,NaughtyFilter &cm)
{
    std::string clientip;
    bool use_xforwardedfor;
    use_xforwardedfor = false;
    if (o.use_xforwardedfor == 1) {
        if (o.net.xforwardedfor_filter_ip.size() > 0) {
            const char *ip = peercon.getPeerIP().c_str();
            for (unsigned int i = 0; i < o.net.xforwardedfor_filter_ip.size(); i++) {
                if (strcmp(ip, o.net.xforwardedfor_filter_ip[i].c_str()) == 0) {
                    use_xforwardedfor = true;
                    break;
                }
            }
        } else {
            use_xforwardedfor = true;
        }
    }

    if (use_xforwardedfor) {
        // grab the X-Forwarded-For IP if available
        clientip = h.getXForwardedForIP();
        // otherwise, grab the IP directly from the client connection
        if (clientip.length() == 0)
            clientip = peercon.getPeerIP();
    } else {
        clientip = peercon.getPeerIP();
    }
    int clientport = peercon.getPeerSourcePort();
    int serverport = peercon.getPort();
    DEBUG_auth("Connecting to: ", clientip, "to ask about: ", clientport);
    Socket iq;
    iq.setTimeout(5000);
    int rc = iq.connect(clientip.c_str(), 113); // ident port
    if (rc) {
        DEBUG_auth("Error connecting to obtain ident from: ", clientip);
        return E2AUTH_NOMATCH;
    }
    DEBUG_auth("Connected to:", clientip);
    std::string request;
    request = String(clientport).toCharArray();
    request += ", ";
    request += String(serverport).toCharArray();
    request += "\r\n";

    DEBUG_auth("About to send:", request);
    if (!iq.writeToSocket((char *)request.c_str(), request.length(), 0, 5000)) {
        DEBUG_auth("Error writing to ident connection to: ", clientip);
        iq.close(); // close conection to client
        return -1;
    }
    DEBUG_auth("wrote ident request to:", clientip);

    char buff[8192];
    try {
        iq.getLine(buff, 8192, 5000);
    } catch (std::exception &e) {
        return -2;
    }
    String temp;
    temp = buff; // convert to String
    DEBUG_auth("got ident reply: ", temp, " from: ", clientip);

    iq.close(); // close conection to client
    temp = temp.after(":");
    if (!temp.before(":").contains("USERID")) {
        return -3;
    }
    temp = temp.after(":");
    temp = temp.after(":");
    temp.removeWhiteSpace();
    if (temp.length() > 0) {
        string = temp.toCharArray();
        authrec.user_name = string;
        authrec.user_source = "ident";
	is_real_user = true;
        return E2AUTH_OK;
    }
    return E2AUTH_NOMATCH;
}

int identinstance::init(void *args)
{
    AuthPlugin::init(args);
    StoryBoardOptions::SB_entry_map sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_IDENT;
        story_entry = sen.entry_id;
        o.story.auth_entry_dq.push_back(sen);
        return 0;
    } else {
        E2LOGGER_error("No story_function defined in ident auth plugin config");
        return -1;
    }
}
