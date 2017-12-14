//Defines the DMPlugin base class, and dm_plugin_loader function

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_DOWNLOADMANAGER
#define __HPP_DOWNLOADMANAGER

// INCLUDES

#include "String.hpp"
#include "ConfigVar.hpp"
#include "Socket.hpp"
#include "HTTPHeader.hpp"
#include "ListContainer.hpp"
#include "Plugin.hpp"
#include "DataBuffer.hpp"

#include <stdexcept>

// DECLARATIONS

class DMPlugin;

// class factory functions for DM plugins
typedef DMPlugin *dmcreate_t(ConfigVar &);

// the DMPlugin interface - inherit & implement this to make download managers
class DMPlugin : public Plugin
{
    public:
    DMPlugin(ConfigVar &definition);
    virtual ~DMPlugin(){};

    // plugin initialise/quit routines.
    // if lastplugin is true, this is being loaded as the fallback option,
    // and needn't load in purely request matching related options.
    virtual int init(void *args);
    virtual int quit()
    {
        return 0;
    };

    // will this download manager handle this request?
    virtual bool willHandle(HTTPHeader *requestheader, HTTPHeader *docheader);

    // download the body for the given request
    virtual int in(DataBuffer *d, Socket *sock, Socket *peersock,
        HTTPHeader *requestheader, HTTPHeader *docheader, bool wantall, int *headersent, bool *toobig)
        = 0;

    // send a download link to the client (the actual link, and the clean "display" version of the link)
    virtual bool sendLink(Socket &peersock, String &linkurl, String &prettyurl);

    private:
    // regular expression for matching supported user agents
    RegExp ua_match;
    // if there isn't one, set this flag
    bool alwaysmatchua;

    protected:
    // our configuration values
    // derived classes could definitely have a use for these
    ConfigVar cv;

    // standard lists
    ListContainer mimetypelist;
    ListContainer extensionlist;
    // .. and their enable flags
    bool mimelistenabled;
    bool extensionlistenabled;

    // read managedmimetypelist and managedextensionlist
    bool readStandardLists();
};

// create an instance of the plugin given in the configuration file
DMPlugin *dm_plugin_load(const char *pluginConfigPath);

#endif
