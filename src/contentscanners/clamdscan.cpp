// ClamD content scanning plugin

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../String.hpp"

#include "../ContentScanner.hpp"
#include "../UDSocket.hpp"
#include "../OptionContainer.hpp"

#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;


// DECLARATIONS

// class name is relevant!
class clamdinstance:public CSPlugin
{
public:
	clamdinstance(ConfigVar & definition):CSPlugin(definition), archivewarn(false) {};

	// we are not replacing scanTest or scanMemory
	// but for scanFile and the default scanMemory to work, we need a working scanFile implementation
	int scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
		const char *ip, const char *filename, NaughtyFilter * checkme,
		const String *disposition, const String *mimetype);

	int init(void* args);

private:
	// ClamD UNIX domain socket path
	String udspath;
	// File path prefix for chrooted ClamD
	String pathprefix;
	// Whether or not to just issue a warning on archive limit/encryption warnings
	bool archivewarn;
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

CSPlugin *clamdcreate(ConfigVar & definition)
{
	return new clamdinstance(definition);
}

// end of Class factory

// initialise the plugin
int clamdinstance::init(void* args)
{
	int rc;
	if ((rc = CSPlugin::init(args)) != DGCS_OK)
		return rc;
	
	// read in ClamD UNIX domain socket path 
	udspath = cv["clamdudsfile"];
	if (udspath.length() < 3) {
		if (!is_daemonised)
			std::cerr << "Error reading clamdudsfile option." << std::endl;
		syslog(LOG_ERR, "Error reading clamdudsfile option.");
		return DGCS_ERROR;
		// it would be far better to do a test connection to the file but
		// could not be arsed for now
	}

	// read in path prefix
	pathprefix = cv["pathprefix"];

	archivewarn = cv["archivewarn"] == "on";

	return DGCS_OK;
}

// no need to replace the inheritied scanMemory() which just calls scanFile()
// there is no capability to scan memory with clamdscan as we pass it
// a file name to scan.  So we save the memory to disk and pass that.
// Then delete the temp file.
int clamdinstance::scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user,
	int filtergroup, const char *ip, const char *filename, NaughtyFilter * checkme,
	const String *disposition, const String *mimetype)
{
	lastmessage = lastvirusname = "";
	// mkstemp seems to only set owner permissions, so our AV daemon won't be
	// able to read the file, unless it's running as the same user as us. that's
	// not usually very convenient. so instead, just allow group read on the
	// file, and tell users to make sure the daemongroup option is friendly to
	// the AV daemon's group membership.
	// TODO? chmod can error out with EINTR, we may wish to ignore this
	if (chmod(filename, S_IRGRP|S_IRUSR) != 0) {
		lastmessage = "Error giving ClamD read access to temp file";
		syslog(LOG_ERR, "Could not change file ownership to give ClamD read access: %s", strerror(errno));
		return DGCS_SCANERROR;
	};
	String command("SCAN ");
	if (pathprefix.length()) {
		String fname(filename);
		command += fname.after(pathprefix.toCharArray());
	} else {
		command += filename;
	}
	command += "\r\n";
#ifdef DGDEBUG
	std::cerr << "clamdscan command:" << command << std::endl;
#endif
	UDSocket stripedsocks;
	if (stripedsocks.getFD() < 0) {
		lastmessage = "Error opening socket to talk to ClamD";
		syslog(LOG_ERR, "Error creating socket for talking to ClamD");
		return DGCS_SCANERROR;
	}
	if (stripedsocks.connect(udspath.toCharArray()) < 0) {
		lastmessage = "Error connecting to ClamD socket";
		syslog(LOG_ERR, "Error connecting to ClamD socket");
		stripedsocks.close();
		return DGCS_SCANERROR;
	}
	try {
		stripedsocks.writeString(command.toCharArray());
	} catch(std::exception &e) {
		stripedsocks.close();
		lastmessage = "Exception whilst writing to ClamD socket: ";
		lastmessage += e.what();
		syslog(LOG_ERR, "Exception whilst writing to ClamD socket: %s", e.what());
		return DGCS_SCANERROR;
	}
	char *buff = new char[4096];
	int rc;
	try {
		rc = stripedsocks.getLine(buff, 4096, o.content_scanner_timeout);
	} catch(std::exception & e) {
		delete[]buff;
		stripedsocks.close();
		lastmessage = "Exception whist reading ClamD socket: ";
		lastmessage += e.what();
		syslog(LOG_ERR, "Exception whilst reading ClamD socket: %s", e.what());
		return DGCS_SCANERROR;
	}
	String reply(buff);
	delete[]buff;
	reply.removeWhiteSpace();
#ifdef DGDEBUG
	std::cout << "Got from clamdscan: " << reply << std::endl;
#endif
	stripedsocks.close();
	if (reply.endsWith("ERROR")) {
		lastmessage = reply;
		syslog(LOG_ERR, "ClamD error: %s", reply.toCharArray());
		return DGCS_SCANERROR;
	}
	else if (reply.endsWith("FOUND")) {
		lastvirusname = reply.after(": ").before(" FOUND");
		// format is:
		// /foo/path/file: foovirus FOUND
#ifdef DGDEBUG
		std::cerr << "clamdscan INFECTED! with: " << lastvirusname << std::endl;
#endif
		if (archivewarn && (lastvirusname.contains(".Exceeded") || lastvirusname.contains(".Encrypted"))) {
#ifdef DGDEBUG
			std::cerr << "clamdscan: detected an ArchiveBlockMax \"virus\"; logging warning only" << std::endl;
#endif
			lastmessage = "Archive not fully scanned: "+lastvirusname;
			
			
			return DGCS_WARNING;
		}
		
		blockFile(NULL,NULL,checkme);
		return DGCS_INFECTED;
	}
	// must be clean
	// Note: we should really check what the output of a "clean" message actually looks like,
	// and check explicitly for that, but the ClamD documentation is sparse on output formats.
#ifdef DGDEBUG
	std::cerr << "clamdscan - he say yes (clean)" << std::endl;
#endif
	return DGCS_CLEAN;
}
