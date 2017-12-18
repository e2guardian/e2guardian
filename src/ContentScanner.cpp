// Implements CSPlugin class and cs_plugin_loader base class

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#include <string>

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "String.hpp"
#include "NaughtyFilter.hpp"
#include "ContentScanner.hpp"
#include "ConfigVar.hpp"
#include "OptionContainer.hpp"

#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <cerrno>

// GLOBALS
extern bool is_daemonised;
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
        return DGCS_ERROR; //include
    } // these
    return DGCS_OK;
}

// make a temporary file for storing data which is to be scanned
// returns FD in int and saves filename to String pointer
// filename is not used as input
int CSPlugin::makeTempFile(String *filename)
{
    int tempfilefd;
    String tempfilepath(o.download_dir.c_str());
    tempfilepath += "/tfXXXXXX";
    char *tempfilepatharray = new char[tempfilepath.length() + 1];
    strcpy(tempfilepatharray, tempfilepath.toCharArray());
    //	mode_t mask = umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP); // this mask is reversed
    umask(0007); // only allow access to e2g user and group
    if ((tempfilefd = mkstemp(tempfilepatharray)) < 1) {
#ifdef DGDEBUG
        std::cerr << "error creating cs temp " << tempfilepath << ": " << strerror(errno) << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Could not create cs temp file.");
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
#ifdef DGDEBUG
        std::cerr << "Error creating temp file in writeMemoryTempFile." << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error creating temp file in writeMemoryTempFile.");
        return DGCS_ERROR;
    }
    errno = 0;
#ifdef DGDEBUG
    std::cout << "About to writeMemoryTempFile " << (*filename) << " size: " << objectsize << std::endl;
#endif

    while (true) {
        if (write(tempfd, object, objectsize) < 0) {
            if (errno == EINTR) {
                continue; // was interupted by a signal so restart
            }
        }
        break; // end the while
    }
    close(tempfd); // finished writing so close file
    return DGCS_OK; // all ok
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
    if (writeMemoryTempFile(object, objectsize, &tempfilepath) != DGCS_OK) {
#ifdef DGDEBUG
        std::cerr << "Error creating/writing temp file for scanMemory." << std::endl;
#endif
        syslog(LOG_ERR, "%s", "Error creating/writing temp file for scanMemory.");
        return DGCS_SCANERROR;
    }
    int rc = scanFile(requestheader, docheader, user, foc, ip, tempfilepath.toCharArray(), checkme, disposition, mimetype);
#ifndef DGDEBUG
    syslog(LOG_ERR, "clamdudsfile remove file %s", tempfilepath.toCharArray());
    unlink(tempfilepath.toCharArray()); // delete temp file
#endif
    return rc;
}

// read in all the lists of various things we do not wish to scan
bool CSPlugin::readStandardLists()
{
    exceptionvirusmimetypelist.reset(); // incase this is a reload
    exceptionvirusextensionlist.reset();
    exceptionvirussitelist.reset();
    exceptionvirusurllist.reset();
    if (!exceptionvirusmimetypelist.readItemList(cv["exceptionvirusmimetypelist"].toCharArray(), false, 0)) {
        if (!is_daemonised) {
            std::cerr << "Error opening exceptionvirusmimetypelist" << std::endl;
        }
        syslog(LOG_ERR, "%s", "Error opening exceptionvirusmimetypelist");
        return false;
    }
    exceptionvirusmimetypelist.doSort(false);
    if (!exceptionvirusextensionlist.readItemList(cv["exceptionvirusextensionlist"].toCharArray(), false, 0)) {
        if (!is_daemonised) {
            std::cerr << "Error opening exceptionvirusextensionlist" << std::endl;
        }
        syslog(LOG_ERR, "%s", "Error opening exceptionvirusextensionlist");
        return false;
    }
    exceptionvirusextensionlist.doSort(false);
    if (!exceptionvirussitelist.readItemList(cv["exceptionvirussitelist"].toCharArray(), false, 0)) {
        if (!is_daemonised) {
            std::cerr << "Error opening exceptionvirussitelist" << std::endl;
        }
        syslog(LOG_ERR, "%s", "Error opening exceptionvirussitelist");
        return false;
    }
    exceptionvirussitelist.doSort(false);
    if (!exceptionvirusurllist.readItemList(cv["exceptionvirusurllist"].toCharArray(), true, 0)) {
        if (!is_daemonised) {
            std::cerr << "Error opening exceptionvirusurllist" << std::endl;
        }
        syslog(LOG_ERR, "%s", "Error opening exceptionvirusurllist");
        return false;
    }
    exceptionvirusurllist.doSort(true);
    return true;
}

// Test whether or not a particular request's incoming/outgoing data should be scanned.
// This is an early-stage (request headers only) test; no other info is known about
// the actual data itself when this is called.
int CSPlugin::willScanRequest(const String &url, const char *user, FOptionContainer* &foc,
    const char *ip, bool post, bool reconstituted, bool exception, bool bypass)
{
    // Most content scanners only deal with original, unmodified content
    if (reconstituted) {
#ifdef DGDEBUG
        std::cout << "willScanRequest: ignoring reconstituted data" << std::endl;
#endif
        return DGCS_NOSCAN;
    }

    // Deal with POST file uploads conditionally, but subject only to the "scanpost"
    // option, not to the domain & URL lists - uploading files does not have the same
    // implications as downlaoding them.
    if (post) {
        if (scanpost) {
#ifdef DGDEBUG
            std::cout << "willScanRequest: I'm interested in uploads" << std::endl;
#endif
            return DGCS_NEEDSCAN;
        } else {
#ifdef DGDEBUG
            std::cout << "willScanRequest: Not interested in uploads" << std::endl;
#endif
            return DGCS_NOSCAN;
        }
    }

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
#ifdef DGDEBUG
        std::cout << "willScanRequest: ignoring our own webserver" << std::endl;
#endif
        return DGCS_NOSCAN;
    }

    // exceptionvirussitelist
    tempurl = domain;
    while (tempurl.contains(".")) {
        if (exceptionvirussitelist.findInList(tempurl.toCharArray(), lc) != NULL) {
#ifdef DGDEBUG
            std::cout << "willScanRequest: ignoring exception virus site" << std::endl;
#endif
            return DGCS_NOSCAN; // exact match
        }
        tempurl = tempurl.after("."); // check for being in higher level domains
    }
    if (tempurl.length() > 1) {
        // allows matching of .tld
        tempurl = "." + tempurl;
        if (exceptionvirussitelist.findInList(tempurl.toCharArray(), lc) != NULL) {
#ifdef DGDEBUG
            std::cout << "willScanRequest: ignoring exception virus site" << std::endl;
#endif
            return DGCS_NOSCAN; // exact match
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
#ifdef DGDEBUG
                    std::cout << "willScanRequest: ignoring exception virus URL" << std::endl;
#endif
                    return DGCS_NOSCAN; // matches /blah/ or /blah/foo but not /blahfoo
                }
            } else {
#ifdef DGDEBUG
                std::cout << "willScanRequest: ignoring exception virus URL" << std::endl;
#endif
                return DGCS_NOSCAN; // exact match
            }
        }
        tempurl = tempurl.after("."); // check for being in higher level domains
    }

#ifdef DGDEBUG
    std::cout << "willScanRequest: I'm interested" << std::endl;
#endif
    return DGCS_NEEDSCAN;
}

// Test whether or not a particular request's incoming/outgoing data should be scanned.
// This is a later-stage test; info is known about the actual data itself when this is called.
int CSPlugin::willScanData(const String &url, const char *user, FOptionContainer* &foc, const char *ip, bool post,
    bool reconstituted, bool exception, bool bypass, const String &disposition, const String &mimetype,
    off_t size)
{
    String lc;
    //exceptionvirusmimetypelist
    if (mimetype.length() > 2) {
        if (exceptionvirusmimetypelist.findInList(mimetype.toCharArray(), lc) != NULL) {
#ifdef DGDEBUG
            std::cout << "willScanData: ignoring exception MIME type (" << mimetype.c_str() << ")" << std::endl;
#endif
            return DGCS_NOSCAN; // match
        }
    }

    //exceptionvirusextensionlist
    String extension;
    if (disposition.length() > 2) {
// If we have a content-disposition, determine file extension from that
#ifdef DGDEBUG
        std::cout << "disposition: " << disposition << std::endl;
#endif
        std::string::size_type start = disposition.find("filename=");
        if (start != std::string::npos) {
            start += 9;
            char endchar = ';';
            if (disposition[start] == '"') {
                endchar = '"';
                ++start;
            }
            std::string::size_type end = disposition.find(endchar, start);
            if (end != std::string::npos)
                extension = disposition.substr(start, end - start);
            else
                extension = disposition.substr(start);
        }
        while (extension.contains(".")) {
            extension = extension.after(".");
        }
        extension = "." + extension;
#ifdef DGDEBUG
        std::cout << "extension from disposition: " << extension << std::endl;
#endif
    } else {
        // Otherwise, determine it from the URL
        String urld(HTTPHeader::decode(url)), path;
        urld.removeWhiteSpace();
        urld.toLower();
        urld.removePTP();

        if (urld.contains("/")) {
            path = urld.after("/");
            path.hexDecode();
            path.realPath();
        }

        if (!path.contains("?")) {
            extension = path;
        } else if (mimetype.contains("application/")) {
            extension = path;
            if (extension.contains("?")) {
                extension = extension.before("?");
            }
        }
#ifdef DGDEBUG
        std::cout << "extension from URL: " << extension << std::endl;
#endif
    }
    if (extension.contains(".")) {
        if (exceptionvirusextensionlist.findEndsWith(extension.toCharArray(), lc) != NULL) {
#ifdef DGDEBUG
            std::cout << "willScanData: ignoring exception file extension (" << extension.c_str() << ")" << std::endl;
#endif
            return DGCS_NOSCAN; // match
        }
    }

#ifdef DGDEBUG
    std::cout << "willScanData: I'm interested" << std::endl;
#endif
    return DGCS_NEEDSCAN;
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

#ifdef ENABLE_CLAMD
    if (plugname == "clamdscan") {
#ifdef DGDEBUG
        std::cout << "Enabling ClamDscan CS plugin" << std::endl;
#endif
        return clamdcreate(cv);
    }
#endif

#ifdef ENABLE_AVASTD
    if (plugname == "avastdscan") {
#ifdef DGDEBUG
        std::cout << "Enabling AvastDscan CS plugin" << std::endl;
#endif
        return avastdcreate(cv);
    }
#endif

#ifdef ENABLE_KAVD
    if (plugname == "kavdscan") {
#ifdef DGDEBUG
        std::cout << "Enabling KAVDscan CS plugin" << std::endl;
#endif
        return kavdcreate(cv);
    }
#endif

#ifdef ENABLE_ICAP
    if (plugname == "icapscan") {
#ifdef DGDEBUG
        std::cout << "Enabling ICAPscan CS plugin" << std::endl;
#endif
        return icapcreate(cv);
    }
#endif

#ifdef ENABLE_COMMANDLINE
    if (plugname == "commandlinescan") {
#ifdef DGDEBUG
        std::cout << "Enabling command-line CS plugin" << std::endl;
#endif
        return commandlinecreate(cv);
    }
#endif

    if (!is_daemonised) {
        std::cerr << "Unable to load plugin: " << pluginConfigPath << std::endl;
    }
    syslog(LOG_ERR, "Unable to load plugin %s\n", pluginConfigPath);
    return NULL;
}
