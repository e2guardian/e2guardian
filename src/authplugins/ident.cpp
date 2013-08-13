// Ident server auth plugin

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../Auth.hpp"
#include "../OptionContainer.hpp"

#include <syslog.h>


// GLOBALS

extern OptionContainer o;


// DECLARATIONS

// class name is relevant!
class identinstance:public AuthPlugin
{
public:
	identinstance(ConfigVar &definition):AuthPlugin(definition) {};
	int identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string);
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

AuthPlugin *identcreate(ConfigVar & definition)
{
	return new identinstance(definition);
}

// end of Class factory

// ident server username extraction
// checkme: needs better error reporting
int identinstance::identify(Socket& peercon, Socket& proxycon, HTTPHeader &h, std::string &string)
{
	std::string clientip;
	if (o.use_xforwardedfor) {
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
#ifdef DGDEBUG
	std::cout << "Connecting to: " << clientip << std::endl;
	std::cout << "to ask about: " << clientport << std::endl;
#endif
	Socket iq;
	iq.setTimeout(5);
	int rc = iq.connect(clientip.c_str(), 113);  // ident port
	if (rc) {
#ifdef DGDEBUG
		std::cerr << "Error connecting to obtain ident from: " << clientip << std::endl;
#endif
		return DGAUTH_NOMATCH;
	}
#ifdef DGDEBUG
	std::cout << "Connected to:" << clientip << std::endl;
#endif
	std::string request;
	request = String(clientport).toCharArray();
	request += ", ";
	request += String(serverport).toCharArray();
	request += "\r\n";
#ifdef DGDEBUG
	std::cout << "About to send:" << request << std::endl;
#endif
	if (!iq.writeToSocket((char *) request.c_str(), request.length(), 0, 5)) {
#ifdef DGDEBUG
		std::cerr << "Error writing to ident connection to: " << clientip << std::endl;
#endif
		iq.close();  // close conection to client
		return -1;
	}
#ifdef DGDEBUG
	std::cout << "wrote ident request to:" << clientip << std::endl;
#endif
	char buff[8192];
	try {
		iq.getLine(buff, 8192, 5);
	} catch(std::exception & e) {
		return -2;
	}
	String temp;
	temp = buff;  // convert to String
#ifdef DGDEBUG
	std::cout << "got ident reply: " << temp << " from: " << clientip << std::endl;
#endif
	iq.close();  // close conection to client
	temp = temp.after(":");
	if (!temp.before(":").contains("USERID")) {
		return -3;
	}
	temp = temp.after(":");
	temp = temp.after(":");
	temp.removeWhiteSpace();
	if (temp.length() > 0) {
		string = temp.toCharArray();
		return DGAUTH_OK;
	}
	return DGAUTH_NOMATCH;
}
