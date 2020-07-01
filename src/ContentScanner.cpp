// Implements CSPlugin class and cs_plugin_loader base class

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#include <string>

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "String.hpp"
#include "HTTPHeader.hpp"
#include "NaughtyFilter.hpp"
#include "ContentScanner.hpp"
#include "ConfigVar.hpp"
#include "OptionContainer.hpp"
#include "Logger.hpp"

#include <cstdlib>
#include <deque>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

// GLOBALS
extern OptionContainer o;

// find the class factory functions for the CS plugins we've been configured to build

#ifdef ENABLE_CLAMD
extern cscreate_t clamdcreate;
#endif

#ifdef ENABLE_AVASTD
extern cscreate_t avastdcreate;
#endif

#ifdef ENABLE_ICAP
extern cscreate_t icapcreate;
#endif

#ifdef ENABLE_KAVD
extern cscreate_t kavdcreate;
#endif

#ifdef ENABLE_COMMANDLINE
extern cscreate_t commandlinecreate;
#endif

// IMPLEMENTATION

// CSPlugin class

CSPlugin::CSPlugin(ConfigVar &definition)
    : scanpost(false)
{
    cv = definition;
}

// start the plugin - i.e. read in the configuration
int CSPlugin::init(void *args)
{
    if (cv["scanpost"] == "on")
        scanpost = true;
    else
        scanpost = false;

    if (!readStandardLists()) { //always
        return E2CS_ERROR; //include
    } // these
    return E2CS_OK;
}

// make a temporary file for storing data which is to be scanned
// returns FD in int and saves filename to String pointer
// filename is not used as input
int CSPlugin::makeTempFile(String *filename)
{
    int tempfilefd;
    String tempfilepath(o.download_dir.c_str());
    tempfilepath += "/csXXXXXX";
    char *tempfilepatharray = new char[tempfilepath.length() + 1];
    strcpy(tempfilepatharray, tempfilepath.toCharArray());
    //	mode_t mask = umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP); // this mask is reversed
    umask(0007); // only allow access to e2g user and group
    if ((tempfilefd = mkstemp(tempfilepatharray)) < 1) {
        logger_error("Could not create temp file for contentscanner.");
        tempfilefd = -1;
    } else {
        (*filename) = tempfilepatharray;
    }
    delete[] tempfilepatharray;
    return tempfilefd;
}

// write a temporary file containing the memory buffer which is to be scanned
// if your CS plugin does not have the ability to scan memory directly (e.g. clamdscan), this gets used by the default scanMemory to turn it into a file
int CSPlugin::writeMemoryTempFile(const char *object, unsigned int objectsize, String *filename)
{
    int tempfd = makeTempFile(filename); // String gets modified
    if (tempfd < 0) {
        logger_error("Error creating temp file in writeMemoryTempFile.");
        return E2CS_ERROR;
    }
    errno = 0;
    logger_debug("About to writeMemoryTempFile ", (*filename), " size: ", objectsize);

    while (true) {
        if (write(tempfd, object, objectsize) < 0) {
            if (errno == EINTR) {
                continue; // was interupted by a signal so restart
            }
        }
        break; // end the while
    }
    close(tempfd); // finished writing so close file
    return E2CS_OK; // all ok
}

// default implementation of scanMemory, which defers to scanFile.
int CSPlugin::scanMemory(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, FOptionContainer* &foc,
    const char *ip, const char *object, unsigned int objectsize, NaughtyFilter *checkme,
    const String *disposition, const String *mimetype)
{
    // there is no capability to scan memory with some AV as we pass it
    // a file name to scan.  So we save the memory to disk and pass that.
    // Then delete the temp file.
    String tempfilepath;
    if (writeMemoryTempFile(object, objectsize, &tempfilepath) != E2CS_OK) {
        logger_error("Error creating/writing temp file for scanMemory.");
        return E2CS_SCANERROR;
    }
    int rc = scanFile(requestheader, docheader, user, foc, ip, tempfilepath.toCharArray(), checkme, disposition, mimetype);
#ifndef E2DEBUG
    unlink(tempfilepath.toCharArray()); // delete temp file
#endif
    return rc;
}

// read in all the lists of various things we do not wish to scan
bool CSPlugin::readStandardLists()      // this is now done in Storyboard
{
    return true;

#ifdef NOTDEF
    exceptionvirusmimetypelist.reset(); // incase this is a reload
    exceptionvirusextensionlist.reset();
    exceptionvirussitelist.reset();
    exceptionvirusurllist.reset();
    if (!exceptionvirusmimetypelist.readItemList(cv["exceptionvirusmimetypelist"].toCharArray(), false, 0)) {
        logger_error("Error opening exceptionvirusmimetypelist");
        return false;
    }
    exceptionvirusmimetypelist.doSort(false);
    if (!exceptionvirusextensionlist.readItemList(cv["exceptionvirusextensionlist"].toCharArray(), false, 0)) {
        logger_error("Error opening exceptionvirusextensionlist");
        return false;
    }
    exceptionvirusextensionlist.doSort(false);
    if (!exceptionvirussitelist.readItemList(cv["exceptionvirussitelist"].toCharArray(), false, 0)) {
        logger_error("Error opening exceptionvirussitelist");
        return false;
    }
    exceptionvirussitelist.doSort(false);
    if (!exceptionvirusurllist.readItemList(cv["exceptionvirusurllist"].toCharArray(), true, 0)) {
        logger_error("Error opening exceptionvirusurllist");
        return false;
    }
    exceptionvirusurllist.doSort(true);
    return true;
#endif
}

// Test whether or not a particular request's incoming/outgoing data should be scanned.
// This is an early-stage (request headers only) test; no other info is known about
// the actual data itself when this is called.
int CSPlugin::willScanRequest(const String &url, const char *user, FOptionContainer* &foc,
    const char *ip, bool post, bool reconstituted, bool exception, bool bypass)
{
    // Most content scanners only deal with original, unmodified content
    if (reconstituted) {
        logger_debug("willScanRequest: ignoring reconstituted data");
        return E2CS_NOSCAN;
    }

    // Deal with POST file uploads conditionally, but subject only to the "scanpost"
    // option, not to the domain & URL lists - uploading files does not have the same
    // implications as downlaoding them.
    if (post) {
        if (scanpost) {
            logger_debug("willScanRequest: I'm interested in uploads");
            return E2CS_NEEDSCAN;
        } else {
            logger_debug("willScanRequest: Not interested in uploads");
            return E2CS_NOSCAN;
        }
    }


   // all list checkng is now done in Storyboard request
    // and filetype checking in Storyboard response
    //
    return E2CS_NEEDSCAN;

#ifdef NOTDEF
    String urld(HTTPHeader::decode(url));
    String lc;
    urld.removeWhiteSpace();
    urld.toLower();
    urld.removePTP();
    String domain, tempurl, foundurl, path;
    unsigned int fl;
    if (urld.contains("/")) {
        domain = urld.before("/");
        path = "/" + urld.after("/");
        path.hexDecode();
        path.realPath();
    } else {
        domain = urld;
    }

    // Don't scan the web server which hosts the access denied page
    if (((foc->reporting_level == 1) || (foc->reporting_level == 2))
        && domain.startsWith(foc->access_denied_domain)) {
        logger_debug("willScanRequest: ignoring our own webserver");
        return E2CS_NOSCAN;
    }

    // exceptionvirussitelist
    tempurl = domain;
    while (tempurl.contains(".")) {
        if (exceptionvirussitelist.findInList(tempurl.toCharArray(), lc) != NULL) {
            logger_debug("willScanRequest: ignoring exception virus site");
            return E2CS_NOSCAN; // exact match
        }
        tempurl = tempurl.after("."); // check for being in higher level domains
    }
    if (tempurl.length() > 1) {
        // allows matching of .tld
        tempurl = "." + tempurl;
        if (exceptionvirussitelist.findInList(tempurl.toCharArray(), lc) != NULL) {
            logger_debug("willScanRequest: ignoring exception virus site");
            return E2CS_NOSCAN; // exact match
        }
    }

    // exceptionvirusurllist
    tempurl = domain + path;
    if (tempurl.endsWith("/")) {
        tempurl.chop(); // chop off trailing / if any
    }
    while (tempurl.before("/").contains(".")) {
        char *i = exceptionvirusurllist.findStartsWith(tempurl.toCharArray(),lc );
        if (i != NULL) {
            foundurl = i;
            fl = foundurl.length();
            if (tempurl.length() > fl) {
                unsigned char c = tempurl[fl];
                if (c == '/' || c == '?' || c == '&' || c == '=') {
                    logger_debug("willScanRequest: ignoring exception virus URL");
                    return E2CS_NOSCAN; // matches /blah/ or /blah/foo but not /blahfoo
                }
            } else {
                logger_debug("willScanRequest: ignoring exception virus URL");
                return E2CS_NOSCAN; // exact match
            }
        }
        tempurl = tempurl.after("."); // check for being in higher level domains
    }

    logger_debug("willScanRequest: I'm interested");
    return E2CS_NEEDSCAN;
#endif
}

// Test whether or not a particular request's incoming/outgoing data should be scanned.
// This is a later-stage test; info is known about the actual data itself when this is called.
int CSPlugin::willScanData(const String &url, const char *user, FOptionContainer* &foc, const char *ip, bool post,
    bool reconstituted, bool exception, bool bypass, const String &disposition, const String &mimetype,
    off_t size) {
    // this function is no longer required as mime/extension exceptions are now handled by Storyboard response
    return E2CS_NEEDSCAN; // match
}


//set the blocking information
void CSPlugin::blockFile(std::string *_category, std::string *_message, NaughtyFilter *checkme)
{
    std::string category;
    std::string message;

    if (_category == NULL) {
        category = "Content scanning";
    } else {
        category = *_category;
    }
    if (_message == NULL) {
        message = lastvirusname.toCharArray();
    } else {
        message = *_message;
    }

    checkme->whatIsNaughty = o.language_list.getTranslation(1100);
    if (message.length() > 0) {
        checkme->whatIsNaughty += " ";
        checkme->whatIsNaughty += message.c_str();
    }

    checkme->whatIsNaughtyLog = checkme->whatIsNaughty;
    checkme->whatIsNaughtyCategories = category.c_str();
    checkme->isItNaughty = true;
    checkme->isException = false;
}

// take in a configuration file, find the CSPlugin class associated with the plugname variable, and return an instance
CSPlugin *cs_plugin_load(const char *pluginConfigPath)
{
    ConfigVar cv;

    if (cv.readVar(pluginConfigPath, "=") > 0) {
        logger_error("Unable to load plugin config ", pluginConfigPath);
        return NULL;
    }

    String plugname(cv["plugname"]);
    if (plugname.length() < 1) {
        logger_error("Unable read plugin config plugname variable %s",pluginConfigPath);
        return NULL;
    }

#ifdef ENABLE_CLAMD
    if (plugname == "clamdscan") {
        logger_debug("Enabling ClamDscan CS plugin");
        return clamdcreate(cv);
    }
#endif

#ifdef ENABLE_AVASTD
    if (plugname == "avastdscan") {
        logger_debug("Enabling AvastDscan CS plugin");
        return avastdcreate(cv);
    }
#endif

#ifdef ENABLE_KAVD
    if (plugname == "kavdscan") {
        logger_debug("Enabling KAVDscan CS plugin");
        return kavdcreate(cv);
    }
#endif

#ifdef ENABLE_ICAP
    if (plugname == "icapscan") {
        logger_debug("Enabling ICAPscan CS plugin");
        return icapcreate(cv);
    }
#endif

#ifdef ENABLE_COMMANDLINE
    if (plugname == "commandlinescan") {
        logger_debug("Enabling command-line CS plugin");
        return commandlinecreate(cv);
    }
#endif

    logger_error("Unable to load plugin ", pluginConfigPath);
    return NULL;
}
