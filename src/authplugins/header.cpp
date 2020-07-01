// Header auth plugin

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

// DECLARATIONS
HTTPHeader *reqheader;

// GLOBALS

extern OptionContainer o;
String fname = "";

// class name is relevant!
class headerinstance : public AuthPlugin
{
    public:
    headerinstance(ConfigVar &definition)
        : AuthPlugin(definition)
    {
    	String fname(cv["header"]);
	    o.ident_header_value = fname;
        needs_proxy_query = true;
        client_ip_based = false;
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec);
    int init(void *args);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *headercreate(ConfigVar &definition)
{
    return new headerinstance(definition);
}

// end of Class factory

// proxy auth header username extraction
int headerinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user,auth_rec &authrec)
{
    if (fname.length() < 0) 
   	return E2AUTH_NOMATCH;

    string = h.getAuthHeader();
    if (string.length() > 0) {
        authrec.user_name = string;
        authrec.user_source = "header";
	is_real_user = false;
        return E2AUTH_OK;
    }
    return E2AUTH_NOMATCH;
}

int headerinstance::init(void *args)
{
    OptionContainer::auth_entry sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYA_AUTH_HEADER;
        story_entry = sen.entry_id;
        o.auth_entry_dq.push_back(sen);
	read_def_fg();
        return 0;
    } else {
        logger_error("No story_function defined in header auth plugin config");
        return -1;
    }
}
