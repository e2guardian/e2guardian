// Defines the class interface to be implemented by ContentScanner plugins

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_CONTENTSCANNER
#define __HPP_CONTENTSCANNER


// INCLUDES
#include "NaughtyFilter.hpp"
#include "String.hpp"
#include "ConfigVar.hpp"
#include "DataBuffer.hpp"
#include "Socket.hpp"
#include "HTTPHeader.hpp"
#include "ListContainer.hpp"
#include "FDFuncs.hpp"
#include "Plugin.hpp"
#include <stdexcept>


// DEFINES
#define DGCS_OK 0
#define DGCS_ERROR -1
#define DGCS_WARNING 3

#define DGCS_NOSCAN 0
#define DGCS_NEEDSCAN 1
#define DGCS_TESTERROR -1


#define DGCS_CLEAN 0
#define DGCS_SCANERROR -1
#define DGCS_INFECTED 1
//#define DGCS_CURED 2  // not used
#define DGCS_BLOCKED 4
#define DGCS_MAX 5 // use values above this for custom return codes


// DECLARATIONS

class CSPlugin;

// class factory functions for CS plugins
typedef CSPlugin* cscreate_t(ConfigVar &);

// CS plugin interface proper - to be implemented by plugins themselves
class CSPlugin: public Plugin
{
public:
	//constructor with CS plugin configuration passed in
	CSPlugin(ConfigVar &definition);

	virtual ~CSPlugin() {};

	// Test for whether or nor a particular ContentScanner is likely to be interested
	// in scanning data associated with the given HTTP request.  If "post" is true,
	// the data which will be scanned is outgoing (i.e. POST requests - file uploads &
	// form submissions).  If "reconstituted" is true, the data which will be passed
	// in is not exactly as it appeared in the request (i.e. URL-encoded form data,
	// but with form control names and URL encoding stripped away to leave a single
	// block of text).
	virtual int willScanRequest(const String &url, const char *user, int filtergroup,
		const char *ip, bool post, bool reconstituted, bool exception, bool bypass);

	// Test whether, in addition to the above, a particular ContentScanner is actually
	// interested in the data we have for it.  This is split into a separate function
	// because, for incoming data (as opposed to POST data), we do not have the
	// information necessary for this test until the response has been received.
	// Content disposition & MIME type will be empty if not available, and size will be -1 if
	// not known.
	// Will not be called for request/response data where willScanRequest previously
	// returned false.
	virtual int willScanData(const String &url, const char *user, int filtergroup, const char *ip,
		bool post, bool reconstituted, bool exception, bool bypass, const String &disposition,
		const String &mimetype, off_t size);

	// scanning functions themselves
	// docheader will be NULL if the data is from a POST request, rather than a response
	// disposition & MIME type may be NULL or empty strings, in which case docheader should be checked for them (if it is not NULL itself)
	virtual int scanMemory(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, int filtergroup, const char *ip,
		const char *object, unsigned int objectsize, NaughtyFilter * checkme, const String *disposition = NULL, const String *mimetype = NULL);
	virtual int scanFile(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, int filtergroup, const char *ip,
		const char* filename, NaughtyFilter * checkme, const String *disposition = NULL, const String *mimetype = NULL) = 0;

	const String &getLastMessage() {return lastmessage;};
	const String &getLastVirusName() {return lastvirusname;};

	// start, restart and stop the plugin
	virtual int init(void* args);
	virtual int quit() {return DGCS_OK;};

private:
	// lists of all the various things we may not want to scan
	ListContainer exceptionvirusmimetypelist;
	ListContainer exceptionvirusextensionlist;
	ListContainer exceptionvirussitelist;
	ListContainer exceptionvirusurllist;

protected:
	ConfigVar cv;
	String lastmessage;
	String lastvirusname;

	// whether or not to AV scan POST uploads
	bool scanpost;

	void blockFile(std::string * _category,std::string * _message, NaughtyFilter * checkme);

	// read in scan exception lists
	bool readStandardLists();
	// make & write to temp files, primarily for plugins with no direct memory scanning capability (e.g. clamdscan)
	int makeTempFile(String *filename);
	int writeMemoryTempFile(const char *object, unsigned int objectsize, String *filename);
};

// Return an instance of the plugin defined in the given configuration file
CSPlugin* cs_plugin_load( const char *pluginConfigPath );

#endif
