// Implements dm_plugin_load and base DMPlugin methods

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "DownloadManager.hpp"
#include "ConfigVar.hpp"
#include "OptionContainer.hpp"
#include "RegExp.hpp"

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>


// GLOBALS

extern bool is_daemonised;
extern OptionContainer o;

extern dmcreate_t defaultdmcreate;

// find the class factory functions for any DM plugins we've been configured to build

#ifdef ENABLE_FANCYDM
extern dmcreate_t fancydmcreate;
#endif

#ifdef ENABLE_TRICKLEDM
extern dmcreate_t trickledmcreate;
#endif


// IMPLEMENTATION

//
// DMPlugin
//

// constructor
DMPlugin::DMPlugin(ConfigVar &definition):alwaysmatchua(false), cv(definition), mimelistenabled(false), extensionlistenabled(false)
{
}

// default initialisation procedure
int DMPlugin::init(void* args)
{
	bool lastplugin = *((bool*)args);
	if (!lastplugin) {
		// compile regex for matching supported user agents
		String r(cv["useragentregexp"]);
		if (r.length() > 0) {
#ifdef DGDEBUG
			std::cout<<"useragent regexp: "<<r<<std::endl;
#endif
			ua_match.comp(r.toCharArray());
		} else {
			// no useragent regex? then default to .*
#ifdef DGDEBUG
			std::cout<<"no useragent regular expression; defaulting to .*"<<std::endl;
#endif
			alwaysmatchua = true;
		}
		if (!readStandardLists())
			return -1;
	}
#ifdef DGDEBUG
	else
		std::cout<<"Fallback DM plugin; no matching options loaded"<<std::endl;
#endif
	return 0;	
}

// default method for sending the client a download link
void DMPlugin::sendLink(Socket &peersock, String &linkurl, String &prettyurl)
{
	// 1220 "<p>Scan complete.</p><p>Click here to download: "
	String message(o.language_list.getTranslation(1220));
	message += "<a href=\"" + linkurl + "\">" + prettyurl + "</a></p></body></html>\n";
	peersock.writeString(message.toCharArray());
}

// default method for deciding whether we will handle a request
bool DMPlugin::willHandle(HTTPHeader *requestheader, HTTPHeader *docheader)
{
	// match user agent first (quick)
	if (!(alwaysmatchua || ua_match.match(requestheader->userAgent().toCharArray())))
		return false;
	
	// then check standard lists (mimetypes & extensions)

	// mimetypes
	String mimetype("");
	bool matchedmime = false;
	if (mimelistenabled) {
		mimetype = docheader->getContentType();
#ifdef DGDEBUG
		std::cout<<"mimetype: "<<mimetype<<std::endl;
#endif
		if (mimetypelist.findInList(mimetype.toCharArray()) == NULL) {
			if (!extensionlistenabled)
				return false;
		} else
			matchedmime = true;
	}
	
	if (extensionlistenabled && !matchedmime) {
		// determine the extension
		String path(requestheader->decode(requestheader->getUrl()));
		path.removeWhiteSpace();
		path.toLower();
		path.removePTP();
		path = path.after("/");
		path.hexDecode();
		path.realPath();
		String disposition(docheader->disposition());
		String extension;
		if (disposition.length() > 2) {
			extension = disposition;
			while (extension.contains(".")) {
				extension = extension.after(".");
			}
			extension = "." + extension;
		} else {
			if (!path.contains("?")) {
				extension = path;
			}
			else {
				if (mimetype.length() == 0)
					mimetype = docheader->getContentType();
				if (mimetype.contains("application/")) {
					extension = path;
					if (extension.contains("?")) {
						extension = extension.before("?");
					}
				}
			}
		}
	#ifdef DGDEBUG
		std::cout<<"extension: "<<extension<<std::endl;
	#endif
		// check the extension list
		if (!extension.contains(".") || (extensionlist.findEndsWith(extension.toCharArray()) == NULL))
				return matchedmime;
	}

	return true;
}

// read in all the lists of various things we wish to handle
bool DMPlugin::readStandardLists()
{
	mimetypelist.reset();  // incase this is a reload
	extensionlist.reset();

	String filename(cv["managedmimetypelist"]);
	if (filename.length() > 0) {
		if (!mimetypelist.readItemList(filename.toCharArray(), false, 0)) {
			if (!is_daemonised) {
				std::cerr << "Error opening managedmimetypelist" << std::endl;
			}
			syslog(LOG_ERR, "Error opening managedmimetypelist");
			return false;
		}
		mimetypelist.doSort(false);
		mimelistenabled = true;
	} else {
		mimelistenabled = false;
	}
	
	filename = cv["managedextensionlist"];
	if (filename.length() > 0) {
		if (!extensionlist.readItemList(filename.toCharArray(), false, 0)) {
			if (!is_daemonised) {
				std::cerr << "Error opening managedextensionlist" << std::endl;
			}
			syslog(LOG_ERR, "Error opening managedextensionlist");
			return false;
		}
		extensionlist.doSort(false);
		extensionlistenabled = true;
	} else {
		extensionlistenabled = false;
	}
	
	return true;
}

// take in a DM plugin configuration file, find the DMPlugin descendent matching the value of plugname, and store its class factory funcs for later use
DMPlugin* dm_plugin_load(const char *pluginConfigPath)
{
	ConfigVar cv;

	if (cv.readVar(pluginConfigPath, "=") > 0) {
		if (!is_daemonised) {
			std::cerr << "Unable to load plugin config: " << pluginConfigPath << std::endl;
		}
		syslog(LOG_ERR, "Unable to load plugin config %s", pluginConfigPath);
		return NULL;
	}

	String plugname(cv["plugname"]);

	if (plugname.length() < 1) {
		if (!is_daemonised) {
			std::cerr << "Unable read plugin config plugname variable: " << pluginConfigPath << std::endl;
		}
		syslog(LOG_ERR, "Unable read plugin config plugname variable %s", pluginConfigPath);
		return NULL;
	}

	if (plugname == "default") {
#ifdef DGDEBUG
		std::cout << "Enabling default DM plugin" << std::endl;
#endif
		return defaultdmcreate(cv);
	}
	
#ifdef ENABLE_FANCYDM
	if (plugname == "fancy") {
#ifdef DGDEBUG
		std::cout << "Enabling fancy DM plugin" << std::endl;
#endif
		return fancydmcreate(cv);
	}
#endif

#ifdef ENABLE_TRICKLEDM
	if (plugname == "trickle") {
#ifdef DGDEBUG
		std::cout << "Enabling trickle DM plugin" << std::endl;
#endif
		return trickledmcreate(cv);
	}
#endif

	if (!is_daemonised) {
		std::cerr << "Unable to load plugin: " << plugname << std::endl;
	}
	syslog(LOG_ERR, "Unable to load plugin %s", plugname.toCharArray());
	return NULL;
}
