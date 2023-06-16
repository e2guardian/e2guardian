// Implements dm_plugin_load and base DMPlugin methods

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "DownloadManager.hpp"
#include "ConfigVar.hpp"
#include "OptionContainer.hpp"
#include "ConnectionHandler.hpp"
#include "RegExp.hpp"
#include "Logger.hpp"

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// GLOBALS

extern OptionContainer o;

extern dmcreate_t defaultdmcreate;

// find the class factory functions for any DM plugins we've been configured to build

extern dmcreate_t fancydmcreate;

extern dmcreate_t trickledmcreate;

// IMPLEMENTATION

//
// DMPlugin
//

// constructor
DMPlugin::DMPlugin(ConfigVar &definition)
    : alwaysmatchua(false), cv(definition)
{
}

// default initialisation procedure
int DMPlugin::init(void *args)
{
    return 0;
}

// default method for sending the client a download link
bool DMPlugin::sendLink(Socket &peersock, String &linkurl, String &prettyurl)
{
    // 1220 "<p>Scan complete.</p><p>Click here to download: "
    String message(o.language_list.getTranslation(1220));
    message += "<a href=\"" + linkurl + "\">" + prettyurl + "</a></p></body></html>\n";
    return peersock.writeString(message.toCharArray());
}
#ifdef NOTDEF
// default method for deciding whether we will handle a request
bool DMPlugin::willHandle(HTTPHeader *requestheader, HTTPHeader *docheader)
{
    // match user agent first (quick)
    RegResult Rre;
    if (!(alwaysmatchua || ua_match.match(requestheader->userAgent().toCharArray(),Rre)))
        return false;

    // then check standard lists (mimetypes & extensions)

    // mimetypes
    String mimetype("");
    bool matchedmime = false;
    if (mimelistenabled) {
        mimetype = docheader->getContentType();
        DEBUG_dwload("mimetype: ", mimetype);
        String lc;
        if (mimetypelist.findInList(mimetype.toCharArray(), lc) == NULL) {
            if (!extensionlistenabled)
                return false;
        } else
            matchedmime = true;    
    } else {
        DEBUG_dwload("NO mimelistenabled!");
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
            } else {
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
        DEBUG_dwload("extension: ", extension);
        // check the extension list
        String lc;
        if (!extension.contains(".") || (extensionlist.findEndsWith(extension.toCharArray(), lc) == NULL))
            return matchedmime;
    } else {
        DEBUG_dwload("NO extensionlistenabled!");
    }


    return true;
}
#endif

#ifdef NOTDEF
// read in all the lists of various things we wish to handle
bool DMPlugin::readStandardLists()
{
    mimetypelist.reset(); // incase this is a reload
    extensionlist.reset();

    String filename(cv["managedmimetypelist"]);
    if (filename.length() > 0) {
        if (!mimetypelist.readItemList(filename.toCharArray(),"", false, 0)) {
            E2LOGGER_error("Error opening managedmimetypelist");
            return false;
        }
        mimetypelist.doSort(false);
        mimelistenabled = true;
    } else {
        mimelistenabled = false;
    }

    filename = cv["managedextensionlist"];
    if (filename.length() > 0) {
        if (!extensionlist.readItemList(filename.toCharArray(), "", false, 0)) {
            E2LOGGER_error("Error opening managedextensionlist");
            return false;
        }
        extensionlist.doSort(false);
        extensionlistenabled = true;
    } else {
        extensionlistenabled = false;
    }

    return true;
}
#endif

// take in a DM plugin configuration file, find the DMPlugin descendent matching the value of plugname, and store its class factory funcs for later use
DMPlugin *dm_plugin_load(const char *pluginConfigPath)
{
    ConfigVar cv;

    if (cv.readVar(pluginConfigPath, "=") > 0) {
        E2LOGGER_error("Unable to load plugin config: ", pluginConfigPath);
        return NULL;
    }

    String plugname(cv["plugname"]);

    if (plugname.length() < 1) {
        E2LOGGER_error("Unable read plugin config plugname variable: ", pluginConfigPath);
        return NULL;
    }

    if (plugname == "default") {
        DEBUG_dwload("Enabling default DM plugin");
        return defaultdmcreate(cv);
    }

#ifdef FANCY_READY      // Plug-in not working yet
    if (plugname == "fancy") {
        DEBUG_dwload("Enabling fancy DM plugin");
        return fancydmcreate(cv);
    }
#endif

    if (plugname == "trickle") {
        DEBUG_dwload("Enabling trickle DM plugin");
        return trickledmcreate(cv);
    }

    E2LOGGER_error("Unable to load plugin: ", plugname);
    return NULL;
}
