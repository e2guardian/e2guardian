// Kaspersky AV Daemon content scanning plugin

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

//TODO: Replace error reporting with detailed entries in syslog(LOG_ERR), short entries in lastmessage.


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


// IMPLEMENTATION

// class name is relevant
class kavdinstance:public CSPlugin
{
public:
	kavdinstance(ConfigVar & definition):CSPlugin(definition) {};
	int scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
		const char *ip, const char *filename, NaughtyFilter * checkme,
		const String *disposition, const String *mimetype);

	int init(void* args);

private:
	// UNIX domain socket path for KAVD
	String udspath;
	// File path prefix for chrooted KAVD
	String pathprefix;
};

// class factory code *MUST* be included in every plugin

CSPlugin *kavdcreate(ConfigVar & definition)
{
	return new kavdinstance(definition);
}

// end of Class factory

// initialise plugin
int kavdinstance::init(void* args)
{
	int rc;
	if ((rc = CSPlugin::init(args)) != DGCS_OK)
		return rc;

	udspath = cv["kavdudsfile"];
	if (udspath.length() < 3) {
		if (!is_daemonised)
			std::cerr << "Error reading kavdudsfile option." << std::endl;
		syslog(LOG_ERR, "%s", "Error reading kavdudsfile option.");
		return DGCS_ERROR;
		// it would be far better to do a test connection to the file but
		// could not be arsed for now
	}

	// read in path prefix
	pathprefix = cv["pathprefix"];

	return DGCS_OK;
}


// no need to replace the inheritied scanMemory() which just calls scanFile()
// there is no capability to scan memory with kavdscan as we pass it
// a file name to scan.  So we save the memory to disk and pass that.
// Then delete the temp file.
int kavdinstance::scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
	const char *ip, const char *filename, NaughtyFilter * checkme, const String *disposition, const String *mimetype)
{
	lastvirusname = lastmessage = "";
	// mkstemp seems to only set owner permissions, so our AV daemon won't be
	// able to read the file, unless it's running as the same user as us. that's
	// not usually very convenient. so instead, just allow group read on the
	// file, and tell users to make sure the daemongroup option is friendly to
	// the AV daemon's group membership.
	// chmod can error with EINTR, ignore this?
	if (chmod(filename, S_IRGRP|S_IRUSR) != 0) {
		syslog(LOG_ERR, "Could not change file ownership to give kavd read access: %s", strerror(errno));
		return DGCS_SCANERROR;
	};
	String command("SCAN bPQRSTUW ");
	if (pathprefix.length()) {
		String fname(filename);
		command += fname.after(pathprefix.toCharArray());
	} else {
		command += filename;
	}
	command += "\r\n";
#ifdef DGDEBUG
	std::cerr << "kavdscan command:" << command << std::endl;
#endif
	UDSocket stripedsocks;
	if (stripedsocks.getFD() < 0) {
		syslog(LOG_ERR, "%s", "Error creating socket for talking to kavdscan");
		return DGCS_SCANERROR;
	}
	if (stripedsocks.connect(udspath.toCharArray()) < 0) {
		syslog(LOG_ERR, "%s", "Error connecting to kavdscan socket");
		stripedsocks.close();
		return DGCS_SCANERROR;
	}
	char *buff = new char[4096];
	memset(buff, 0, 4096);
	int rc;
	try {
		// read kaspersky kavdscan (AV Enging Server) - format: 2xx greeting
		rc = stripedsocks.getLine(buff, 4096, o.content_scanner_timeout);
	} catch(std::exception & e) {
	}
	if (buff[0] != '2') {
		delete[]buff;
		stripedsocks.close();
		syslog(LOG_ERR, "%s", "kavdscan did not return ok");
		return DGCS_SCANERROR;
	}
	try {
		stripedsocks.writeString(command.toCharArray());
	}
	catch(std::exception & e) {
		delete[]buff;
		stripedsocks.close();
		syslog(LOG_ERR, "%s", "unable to write to kavdscan");
		return DGCS_SCANERROR;
	}
	try {
		rc = stripedsocks.getLine(buff, 4096, o.content_scanner_timeout);
	}
	catch(std::exception & e) {
		delete[]buff;
		stripedsocks.close();
		syslog(LOG_ERR, "%s", "Error reading kavdscan socket");
		return DGCS_SCANERROR;
	}
	String reply(buff);
#ifdef DGDEBUG
	std::cout << "Got from kavdscan:" << reply << std::endl;
#endif
	if (reply[0] == '2') {	// clean
#ifdef DGDEBUG
		std::cerr << "kavdscan - clean" << std::endl;
#endif
		delete[]buff;
		stripedsocks.close();
		return DGCS_CLEAN;
	}
	if (reply.startsWith("322")) {	// infected
		// patch to handle multiple virii in kavd response
		// originally submitted by cahya <littlecahya@yahoo.de>
		while(reply[0] != '2' && rc != 0) {
			reply.removeWhiteSpace();
			lastvirusname = lastvirusname + " " + reply.after("322-").before(" ");
			try {
				rc = stripedsocks.getLine(buff, 4096, o.content_scanner_timeout);
			}
			catch(std::exception & e) {
				delete[]buff;
				stripedsocks.close();
				syslog(LOG_ERR, "%s", "Error reading kavdscan socket");
				return DGCS_SCANERROR;
			}
			reply = buff;
#ifdef DGDEBUG
			std::cout << "Got from kavdscan:" << reply << std::endl;
#endif
		}
		std::cout << "lastvirusname: " << lastvirusname << std::endl;
		delete[]buff;
		stripedsocks.close();
		
		// format: 322 nastyvirus blah
		blockFile(NULL,NULL,checkme);
		return DGCS_INFECTED;
	}
	delete[]buff;
	stripedsocks.close();
	// must be an error then
	lastmessage = reply;
	return DGCS_SCANERROR;
}
