// ICAP server content scanning plugin

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../String.hpp"

#include "../ContentScanner.hpp"
#include "../OptionContainer.hpp"

#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>		// for gethostby
#include <cstdio>


// DEFINES

#define ICAP_CONTINUE DGCS_MAX+1
#define ICAP_NODATA DGCS_MAX+2


// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;


// DECLARATIONS

// class name is relevant!
class icapinstance:public CSPlugin
{
public:
	icapinstance(ConfigVar & definition):CSPlugin(definition), usepreviews(false), previewsize(0),
		supportsXIF(false), needsBody(false) {};
	
	int willScanRequest(const String &url, const char *user, int filtergroup, const char *ip, bool post,
		bool reconstituted, bool exception, bool bypass);

	int scanMemory(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
		const char *ip, const char *object, unsigned int objectsize, NaughtyFilter * checkme,
		const String *disposition, const String *mimetype);
	int scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
		const char *ip, const char *filename, NaughtyFilter * checkme,
		const String *disposition, const String *mimetype);

	int init(void* args);

private:
	// ICAP server hostname, IP and port
	String icaphost;
	String icapip;
	unsigned int icapport;
	// URL for the AV service
	String icapurl;
	// whether or not to send ICAP message previews, and the preview object size
	bool usepreviews;
	unsigned int previewsize;
	// supports X-Infection-Found and/or needs us to look at the whole body
	bool supportsXIF;
	bool needsBody;

	// Send ICAP request headers to server
	bool doHeaders(Socket & icapsock, HTTPHeader *reqheader, HTTPHeader *respheader, unsigned int objectsize);
	// Check data returned from ICAP server and return one of our standard return codes
	int doScan(Socket & icapsock, HTTPHeader * docheader, const char* object, unsigned int objectsize, NaughtyFilter * checkme);
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

CSPlugin *icapcreate(ConfigVar & definition)
{
	return new icapinstance(definition);
}

// end of Class factory

// don't scan POST data or reconstituted data - wouldn't work for multi-part posts
// without faking request headers, as we are only passed a single part, not the whole request verbatim
int icapinstance::willScanRequest(const String &url, const char *user, int filtergroup, const char *ip,
	bool post, bool reconstituted, bool exception, bool bypass)
{
	if (post || reconstituted)
		return DGCS_NOSCAN;
	else
	{
		return CSPlugin::willScanRequest(url, user, filtergroup, ip,
			post, reconstituted, exception, bypass);
	}
}

// initialise the plugin - determine icap ip, port & url
int icapinstance::init(void* args)
{
	// always include these lists
	if (!readStandardLists()) {
		return DGCS_ERROR;
	}

	icapurl = cv["icapurl"];  // format: icap://icapserver:1344/avscan
	if (icapurl.length() < 3) {
		if (!is_daemonised)
			std::cerr << "Error reading icapurl option." << std::endl;
		syslog(LOG_ERR, "Error reading icapurl option.");
		return DGCS_ERROR;
		// it would be far better to do a test connection
	}
	icaphost = icapurl.after("//");
	icapport = icaphost.after(":").before("/").toInteger();
	if (icapport == 0) {
		icapport = 1344;
	}
	icaphost = icaphost.before("/");
	if (icaphost.contains(":")) {
		icaphost = icaphost.before(":");
	}
	struct hostent *host;
	if ((host = gethostbyname(icaphost.toCharArray())) == 0) {
		if (!is_daemonised)
			std::cerr << "Error resolving icap host address." << std::endl;
		syslog(LOG_ERR, "Error resolving icap host address.");
		return DGCS_ERROR;
	}
	icapip = inet_ntoa(*(struct in_addr *) host->h_addr_list[0]);

#ifdef DGDEBUG
	std::cerr << "ICAP server address:" << icapip << std::endl;
#endif

	// try to connect to the ICAP server and perform an OPTIONS request
	Socket icapsock;
	try {
		if (icapsock.connect(icapip.toCharArray(), icapport) < 0) {
			throw std::runtime_error("Could not connect to server");
		}
		String line("OPTIONS " + icapurl + " ICAP/1.0\r\nHost: " + icaphost + "\r\n\r\n");
		icapsock.writeString(line.toCharArray());
		// parse the response
		char buff[8192];
		// first line - look for 200 OK
		icapsock.getLine(buff, 8192, o.content_scanner_timeout);
		line = buff;
#ifdef DGDEBUG
		std::cout << "ICAP/1.0 OPTIONS response:" << std::endl << line << std::endl;
#endif
		if (line.after(" ").before(" ") != "200") {
			if (!is_daemonised)
				std::cerr << "ICAP response not 200 OK" << std::endl;
			syslog(LOG_ERR, "ICAP response not 200 OK");
			return DGCS_WARNING;
			//throw std::runtime_error("Response not 200 OK");
		}
		while (icapsock.getLine(buff, 8192, o.content_scanner_timeout) > 0) {
			line = buff;
#ifdef DGDEBUG
			std::cout << line << std::endl;
#endif
			if (line.startsWith("\r")) {
				break;
			}
			else if (line.startsWith("Preview:")) {
				usepreviews = true;
				previewsize = line.after(": ").toInteger();
			}
			else if (line.startsWith("Server:")) {
				if (line.contains("AntiVir-WebGate")) {
					needsBody = true;
				}
			}
			else if (line.startsWith("X-Allow-Out:")) {
				if (line.contains("X-Infection-Found")) {
					supportsXIF = true;
				}
			}
		}
		icapsock.close();
	} catch(std::exception& e) {
		if (!is_daemonised)
			std::cerr << "ICAP server did not respond to OPTIONS request: " << e.what() << std::endl;
		syslog(LOG_ERR, "ICAP server did not respond to OPTIONS request: %s", e.what());
		return DGCS_ERROR;
	}
#ifdef DGDEBUG
	if (usepreviews)
		std::cout << "Message previews enabled; size: " << previewsize << std::endl;
	else
		std::cout << "Message previews disabled" << std::endl;
#endif
	return DGCS_OK;
}

// send memory buffer to ICAP server for scanning
int icapinstance::scanMemory(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user, int filtergroup,
	const char *ip, const char *object, unsigned int objectsize, NaughtyFilter * checkme,
	const String *disposition, const String *mimetype)
{
	lastvirusname = lastmessage = "";

	Socket icapsock;

	if (not doHeaders(icapsock, requestheader, docheader, objectsize)) {
		icapsock.close();
		return DGCS_SCANERROR;
	}
#ifdef DGDEBUG
	std::cerr << "About to send memory data to icap" << std::endl;
	if (usepreviews && (objectsize > previewsize))
		std::cerr << "Sending preview first" << std::endl;
#endif
	unsigned int sent = 0;
	if (usepreviews && (objectsize > previewsize)) {
		try {
			if (!icapsock.writeToSocket(object, previewsize, 0, o.content_scanner_timeout)) {
				throw std::runtime_error("standard error");
			}
			sent += previewsize;
			icapsock.writeString("\r\n0\r\n\r\n");
			int rc = doScan(icapsock, docheader, object, objectsize, checkme);
			if (rc != ICAP_CONTINUE)
				return rc;
			// some servers send "continue" immediately followed by another response
			if (icapsock.checkForInput()) {
				int rc = doScan(icapsock, docheader, object, objectsize, checkme);
				if (rc != ICAP_NODATA)
					return rc;
			}
			char objectsizehex[32];
			snprintf(objectsizehex, sizeof(objectsizehex), "%x\r\n", objectsize-previewsize);
			icapsock.writeString(objectsizehex);
		} catch (std::exception& e) {
#ifdef DGDEBUG
			std::cerr << "Exception sending message preview to ICAP: " << e.what() << std::endl;
#endif
			// this *might* just be an early response & closed connection
			if (icapsock.checkForInput()) {
				int rc = doScan(icapsock, docheader, object, objectsize, checkme);
				if (rc != ICAP_NODATA)
					return rc;
			}
			icapsock.close();
			lastmessage = "Exception sending message preview to ICAP";
			syslog(LOG_ERR, "Exception sending message preview to ICAP: %s", e.what());
			return DGCS_SCANERROR;		
		}
	}
	try {
		icapsock.writeToSockete(object + sent, objectsize - sent, 0, o.content_scanner_timeout);
#ifdef DGDEBUG
		std::cout << "total sent to icap: " << objectsize << std::endl;
#endif
		icapsock.writeString("\r\n0\r\n\r\n");  // end marker
#ifdef DGDEBUG
		std::cout << "memory was sent to icap" << std::endl;
#endif
	} catch(std::exception & e) {
#ifdef DGDEBUG
		std::cerr << "Exception sending memory file to ICAP: " << e.what() << std::endl;
#endif
		// this *might* just be an early response & closed connection
		if (icapsock.checkForInput()) {
			int rc = doScan(icapsock, docheader, object, objectsize, checkme);
			if (rc != ICAP_NODATA)
				return rc;
		}
		icapsock.close();
		lastmessage = "Exception sending memory file to ICAP";
		syslog(LOG_ERR, "Exception sending memory file to ICAP: %s", e.what());
		return DGCS_SCANERROR;
	}

	return doScan(icapsock, docheader, object, objectsize, checkme);
}

// send file contents for scanning
int icapinstance::scanFile(HTTPHeader * requestheader, HTTPHeader * docheader, const char *user,
	int filtergroup, const char *ip, const char *filename, NaughtyFilter * checkme,
	const String *disposition, const String *mimetype)
{
	lastmessage = lastvirusname = "";
	int filefd = open(filename, O_RDONLY);
	if (filefd < 0) {
#ifdef DGDEBUG
		std::cerr << "Error opening file (" << filename << "): " << strerror(errno) << std::endl;
#endif
		lastmessage = "Error opening file to send to ICAP";
		syslog(LOG_ERR, "Error opening file to send to ICAP: %s", strerror(errno));
		return DGCS_SCANERROR;
	}
	lseek(filefd, 0, SEEK_SET);
	unsigned int filesize = lseek(filefd, 0, SEEK_END);

	Socket icapsock;
	if (not doHeaders(icapsock, requestheader, docheader, filesize)) {
		icapsock.close();
		close(filefd);
		return DGCS_SCANERROR;
	}

	lseek(filefd, 0, SEEK_SET);
	unsigned int sent = 0;
	char *data = new char[previewsize];
	char *object = new char[100];
	int objectsize = 0;

#ifdef DGDEBUG
	std::cerr << "About to send file data to icap" << std::endl;
	if (usepreviews && (filesize > previewsize))
		std::cerr << "Sending preview first" << std::endl;
#endif
	if (usepreviews && (filesize > previewsize)) {
		try {
			while (sent < previewsize) {
				int rc = readEINTR(filefd, data, previewsize);
				if (rc < 0) {
					throw std::runtime_error("could not read from file");
				}
				if (rc == 0) {
					break;  // should never happen
				}
				if (!icapsock.writeToSocket(data, rc, 0, o.content_scanner_timeout)) {
					throw std::runtime_error("could not write to socket");
				}
				memcpy(object, data, (rc > 100) ? 100 : rc);
				objectsize += (rc > 100) ? 100 : rc;
				sent += rc;
			}
			icapsock.writeString("\r\n0\r\n\r\n");
			int rc = doScan(icapsock, docheader, object, objectsize, checkme);
			if (rc != ICAP_CONTINUE) {
				delete[] data;
				close(filefd);
				return rc;
			}
			// some servers send "continue" immediately followed by another response
			if (icapsock.checkForInput()) {
				int rc = doScan(icapsock, docheader, object, objectsize, checkme);
				if (rc != ICAP_NODATA) {
					delete[] data;
					close(filefd);
					return rc;
				}
			}
			char objectsizehex[32];
			snprintf(objectsizehex, sizeof(objectsizehex), "%x\r\n", filesize-previewsize);
			icapsock.writeString(objectsizehex);
		} catch (std::exception& e) {
#ifdef DGDEBUG
			std::cerr << "Exception sending message preview to ICAP: " << e.what() << std::endl;
#endif
			icapsock.close();
			lastmessage = "Exception sending message preview to ICAP";
			syslog(LOG_ERR, "Exception sending message preview to ICAP: %s", e.what());
			delete[] data;
			close(filefd);
			// this *might* just be an early response & closed connection
			if (icapsock.checkForInput()) {
				int rc = doScan(icapsock, docheader, object, objectsize, checkme);
				if (rc != ICAP_NODATA)
					return rc;
			}
			return DGCS_SCANERROR;		
		}
	}

	delete[] data;
	data = new char[256 * 1024];  // 256k

	try {
		while (sent < filesize) {
			int rc = readEINTR(filefd, data, 256 * 1024);
#ifdef DGDEBUG
			std::cout << "reading icap file rc: " << rc << std::endl;
#endif
			if (rc < 0) {
#ifdef DGDEBUG
				std::cout << "error reading icap file so throwing exception" << std::endl;
#endif
				throw std::runtime_error("could not read from file");
			}
			if (rc == 0) {
#ifdef DGDEBUG
				std::cout << "got zero bytes reading icap file" << std::endl;
#endif
				break;  // should never happen
			}
			memcpy(object + objectsize, data, (rc > (100-objectsize)) ? (100-objectsize) : rc);
			objectsize += (rc > (100-objectsize)) ? (100-objectsize) : rc;
			icapsock.writeToSockete(data, rc, 0, o.content_scanner_timeout);
			sent += rc;
		}
#ifdef DGDEBUG
		std::cout << "total sent to icap: " << sent << std::endl;
#endif
		icapsock.writeString("\r\n0\r\n\r\n");  // end marker
#ifdef DGDEBUG
		std::cout << "file was sent to icap" << std::endl;
#endif
	}
	catch(std::exception & e) {
#ifdef DGDEBUG
		std::cerr << "Exception sending file to ICAP: " << e.what() << std::endl;
#endif
		lastmessage = "Exception sending file to ICAP";
		syslog(LOG_ERR, "Exception sending file to ICAP: %s", e.what());
		delete[]data;
		close(filefd);
		// this *might* just be an early response & closed connection
		if (icapsock.checkForInput()) {
			int rc = doScan(icapsock, docheader, object, objectsize, checkme);
			if (rc != ICAP_NODATA)
				return rc;
		}
		return DGCS_SCANERROR;
	}
	close(filefd);
	delete[] data;
	return doScan(icapsock, docheader, object, objectsize, checkme);
}

// send ICAP request headers, returning success or failure
bool icapinstance::doHeaders(Socket & icapsock, HTTPHeader *reqheader, HTTPHeader *respheader, unsigned int objectsize)
{
	int rc = icapsock.connect(icapip.toCharArray(), icapport);
	if (rc) {
#ifdef DGDEBUG
		std::cerr << "Error connecting to ICAP server" << std::endl;
#endif
		lastmessage = "Error connecting to ICAP server";
		syslog(LOG_ERR, "Error connecting to ICAP server");
		return false;
	}
	char objectsizehex[32];
	// encapsulated HTTP request header:
	// use a dummy unless it proves absolutely necessary to do otherwise,
	// as using real data could lead to e.g. yet another source of password
	// leakage over the network.
	String encapsulatedheader("GET " + reqheader->getUrl() + " HTTP/1.0\r\n\r\n");
	// body chunk size in hex - either full body, or just preview
	if (usepreviews && (objectsize > previewsize)) {
		snprintf(objectsizehex, sizeof(objectsizehex), "%x\r\n", previewsize);
	} else {
		snprintf(objectsizehex, sizeof(objectsizehex), "%x\r\n", objectsize);
	}
	// encapsulated HTTP response header:
	// use real data, because scanners can use this to aid the process
	/*String httpresponseheader;
	for (std::deque<String>::iterator i = respheader->header.begin(); i != respheader->header.end(); i++) {
		httpresponseheader += (*i) + "\r\n";
	}
	httpresponseheader += "\r\n";*/
	String httpresponseheader("HTTP/1.0 200 OK\r\n\r\n");
	// ICAP header itself
	String icapheader("RESPMOD " + icapurl + " ICAP/1.0\r\nHost: " + icaphost + "\r\nAllow: 204\r\nEncapsulated: req-hdr=0, res-hdr=" + String(encapsulatedheader.length()) + ", res-body=" + String(httpresponseheader.length() + encapsulatedheader.length()));
	if (usepreviews && (objectsize > previewsize)) {
		icapheader += "\r\nPreview: " + String(previewsize);
	}
	icapheader += "\r\n\r\n";

#ifdef DGDEBUG
	std::cerr << "About to send icapheader:\n" << icapheader << encapsulatedheader << httpresponseheader << objectsizehex << std::endl;
#endif
	try {
		icapsock.writeString(icapheader.toCharArray());
		icapsock.writeString(encapsulatedheader.toCharArray());
		icapsock.writeString(httpresponseheader.toCharArray());
		icapsock.writeString(objectsizehex);
	}
	catch(std::exception & e) {
#ifdef DGDEBUG
		std::cerr << "Exception sending headers to ICAP: " << e.what() << std::endl;
#endif
		lastmessage = "Exception sending headers to ICAP";
		syslog(LOG_ERR, "Exception sending headers to ICAP: %s", e.what());
		return false;
	}
	return true;
}

// check data received from ICAP server and interpret as virus name & return value
int icapinstance::doScan(Socket & icapsock, HTTPHeader * docheader, const char* object, unsigned int objectsize, NaughtyFilter * checkme)
{
	char *data = new char[8192];
	try {
		String line;
		int rc = icapsock.getLine(data, 8192, o.content_scanner_timeout);
		if (rc == 0)
			return ICAP_NODATA;
		line = data;
#ifdef DGDEBUG
		std::cout << "reply from icap: " << line << std::endl;
#endif
		// reply is of the format:
		// ICAP/1.0 204 No Content Necessary (etc)

		String returncode(line.after(" ").before(" "));

		if (returncode == "204") {
#ifdef DGDEBUG
			std::cerr << "ICAP says clean!" << std::endl;
#endif
			delete[]data;
			return DGCS_CLEAN;
		} else if (returncode == "100") {
#ifdef DGDEBUG
			std::cerr << "ICAP says continue!" << std::endl;
#endif
			// discard rest of headers (usually just a blank line)
			// this is so we are in the right place in the data stream to
			// call doScan() again later, because people like Symantec seem
			// to think sending code 100 then code 204 one after the other
			// is not an abuse of the ICAP specification.
			while (icapsock.getLine(data, 8192, o.content_scanner_timeout) > 0) {
				if (data[0] == 13)
					break;
			}
			delete[]data;
			return ICAP_CONTINUE;
		}
		else if (returncode == "200") {
#ifdef DGDEBUG
			std::cerr << "ICAP says maybe not clean!" << std::endl;
#endif
			while (icapsock.getLine(data, 8192, o.content_scanner_timeout) > 0) {
				if (data[0] == 13)	// end marker
					break;
				line = data;
				// Symantec's engine gives us the virus name in the ICAP headers
				if (supportsXIF && line.startsWith("X-Infection-Found")) {
#ifdef DGDEBUG
					std::cout << "ICAP says infected! (X-Infection-Found)" << std::endl;
#endif
					lastvirusname = line.after("Threat=").before(";");
					delete[]data;
					
					blockFile(NULL,NULL,checkme);
					return DGCS_INFECTED;
				}
			}
			// AVIRA's Antivir gives us 200 in all cases, so
			// - unfortunately - we must pay attention to the encapsulated
			// header/body.
			if (needsBody) {
				// grab & compare the HTTP return code from modified response
				// if it's been modified, assume there's an infection
				icapsock.getLine(data, 8192, o.content_scanner_timeout);
				line = data;
#ifdef DGDEBUG
				std::cout << "Comparing original return code to modified:" << std::endl << docheader->header.front() << std::endl << line << std::endl;
#endif
				int respmodReturnCode = line.after(" ").before(" ").toInteger();
				if (respmodReturnCode != docheader->returnCode()) {
#ifdef DGDEBUG
					std::cerr << "ICAP says infected! (returned header comparison)" << std::endl;
#endif
					delete[] data;
					lastvirusname = "Unknown";

					blockFile(NULL,NULL,checkme);
					return DGCS_INFECTED;
				}
				// ok - headers were identical, so look at encapsulated body
				// discard the rest of the encapsulated headers
				while (icapsock.getLine(data, 8192, o.content_scanner_timeout) > 0) {
					if (data[0] == 13)
						break;
				}
				// grab body chunk size
#ifdef DGDEBUG
				std::cout << "Comparing original body data to modified" << std::endl;
#endif
				icapsock.getLine(data, 8192, o.content_scanner_timeout);
				line = data;
				int bodysize = line.hexToInteger();
				// get, say, the first 100 bytes and compare them to what we
				// originally sent to see if it has been modified
				unsigned int chunksize = (bodysize < 100) ? bodysize : 100;
				if (chunksize > objectsize)
					chunksize = objectsize;
				icapsock.readFromSocket(data, chunksize, 0, o.content_scanner_timeout);
				if (memcmp(data, object, chunksize) == 0) {
#ifdef DGDEBUG
					std::cerr << "ICAP says clean!" << std::endl;
#endif
					delete[]data;
					return DGCS_CLEAN;
				} else {
#ifdef DGDEBUG
					std::cerr << "ICAP says infected! (body byte comparison)" << std::endl;
#endif
					delete[] data;
					lastvirusname = "Unknown";

					blockFile(NULL,NULL,checkme);
					return DGCS_INFECTED;
				}
			}
			// even if we don't find an X-Infection-Found header,
			// the file is still infected!
#ifdef DGDEBUG
			std::cerr << "ICAP says infected! (no further tests)" << std::endl;
#endif
			delete[] data;
			lastvirusname = "Unknown";

			blockFile(NULL,NULL,checkme);
			return DGCS_INFECTED;
		}
		else if (returncode == "404") {
#ifdef DGDEBUG
			std::cerr << "ICAP says no such service!" << std::endl;
#endif
			lastmessage = "ICAP reports no such service";
			syslog(LOG_ERR, "ICAP reports no such service; check your server URL");
			delete[]data;
			return DGCS_SCANERROR;
		} else {
#ifdef DGDEBUG
			std::cerr << "ICAP returned unrecognised response code: " << returncode << std::endl;
#endif
			lastmessage = "ICAP returned unrecognised response code.";
			syslog(LOG_ERR, "ICAP returned unrecognised response code: %s", returncode.toCharArray());
			delete[]data;
			return DGCS_SCANERROR;
		}
		delete[]data;
	}
	catch(std::exception & e) {
#ifdef DGDEBUG
		std::cerr << "Exception getting reply from ICAP: " << e.what() << std::endl;
#endif
		lastmessage = "Exception getting reply from ICAP.";
		syslog(LOG_ERR, "Exception getting reply from ICAP: %s", e.what());
		delete[]data;
		return DGCS_SCANERROR;
	}
	// it is generally NOT a good idea, when using virus scanning,
	// to continue as if nothing went wrong by default!
	return DGCS_SCANERROR;
}
