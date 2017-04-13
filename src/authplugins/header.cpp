// Header auth plugin

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#include "../OptionContainer.hpp" 
#endif

#include "../Auth.hpp"

#include "../OptionContainer.hpp" 
#include <syslog.h>

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
    };
    int identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *headercreate(ConfigVar &definition)
{
    return new headerinstance(definition);
}

// end of Class factory

// proxy auth header username extraction
int headerinstance::identify(Socket &peercon, Socket &proxycon, HTTPHeader &h, std::string &string, bool &is_real_user)
{
    if (fname.length() < 0) 
   	return DGAUTH_NOMATCH;

    string = h.getAuthHeader();
    if (string.length() > 0) {
        return DGAUTH_OK;
    }
    return DGAUTH_NOMATCH;
}
