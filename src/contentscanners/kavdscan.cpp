// Kaspersky AV Daemon content scanning plugin

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "../String.hpp"

#include "../ContentScanner.hpp"
#include "../UDSocket.hpp"
#include "../OptionContainer.hpp"
#include "../Logger.hpp"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// GLOBALS

extern OptionContainer o;

// IMPLEMENTATION

// class name is relevant
class kavdinstance : public CSPlugin
{
    public:
    kavdinstance(ConfigVar &definition)
        : CSPlugin(definition){};
    int scanFile(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, FOptionContainer* &foc,
        const char *ip, const char *filename, NaughtyFilter *checkme,
        const String *disposition, const String *mimetype);

    int init(void *args);

    private:
    // UNIX domain socket path for KAVD
    String udspath;
    // File path prefix for chrooted KAVD
    String pathprefix;
};

// class factory code *MUST* be included in every plugin

CSPlugin *kavdcreate(ConfigVar &definition)
{
    return new kavdinstance(definition);
}

// end of Class factory

// initialise plugin
int kavdinstance::init(void *args)
{
    int rc;
    if ((rc = CSPlugin::init(args)) != E2CS_OK)
        return rc;

    udspath = cv["kavdudsfile"];
    if (udspath.length() < 3) {
        logger_error("Error reading kavdudsfile option.");
        return E2CS_ERROR;
        // it would be far better to do a test connection to the file but
        // could not be arsed for now
    }

    // read in path prefix
    pathprefix = cv["pathprefix"];

    return E2CS_OK;
}

// no need to replace the inheritied scanMemory() which just calls scanFile()
// there is no capability to scan memory with kavdscan as we pass it
// a file name to scan.  So we save the memory to disk and pass that.
// Then delete the temp file.
int kavdinstance::scanFile(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, FOptionContainer* &foc,
    const char *ip, const char *filename, NaughtyFilter *checkme, const String *disposition, const String *mimetype)
{
    lastvirusname = lastmessage = "";
    // mkstemp seems to only set owner permissions, so our AV daemon won't be
    // able to read the file, unless it's running as the same user as us. that's
    // not usually very convenient. so instead, just allow group read on the
    // file, and tell users to make sure the daemongroup option is friendly to
    // the AV daemon's group membership.
    // chmod can error with EINTR, ignore this?
    if (chmod(filename, S_IRGRP | S_IRUSR) != 0) {
        logger_error("Could not change file ownership to give kavd read access: ", strerror(errno));
        return E2CS_SCANERROR;
    };
    String command("SCAN bPQRSTUW ");
    if (pathprefix.length()) {
        String fname(filename);
        command += fname.after(pathprefix.toCharArray());
    } else {
        command += filename;
    }
    command += "\r\n";
    logger_debug("kavdscan command:", command);

    UDSocket stripedsocks;
    if (stripedsocks.getFD() < 0) {
        logger_error("Error creating socket for talking to kavdscan");
        return E2CS_SCANERROR;
    }
    if (stripedsocks.connect(udspath.toCharArray()) < 0) {
        logger_error("Error connecting to kavdscan socket");
        stripedsocks.close();
        return E2CS_SCANERROR;
    }
    char *buff = new char[4096];
    memset(buff, 0, 4096);
    int rc;
    try {
        // read kaspersky kavdscan (AV Enging Server) - format: 2xx greeting
        rc = stripedsocks.getLine(buff, 4096, o.content_scanner_timeout);
    } catch (std::exception &e) {
    }
    if (buff[0] != '2') {
        delete[] buff;
        stripedsocks.close();
        logger_error("kavdscan did not return ok");
        return E2CS_SCANERROR;
    }
    try {
        stripedsocks.writeString(command.toCharArray());
    } catch (std::exception &e) {
        delete[] buff;
        stripedsocks.close();
        logger_error("unable to write to kavdscan");
        return E2CS_SCANERROR;
    }
    try {
        rc = stripedsocks.getLine(buff, 4096, o.content_scanner_timeout);
    } catch (std::exception &e) {
        delete[] buff;
        stripedsocks.close();
        logger_error("Error reading kavdscan socket");
        return E2CS_SCANERROR;
    }
    String reply(buff);
    logger_debug("Got from kavdscan:", reply);

    if (reply[0] == '2') { // clean
        logger_debug("kavdscan - clean");
        delete[] buff;
        stripedsocks.close();
        return E2CS_CLEAN;
    }
    if (reply.startsWith("322")) { // infected
        // patch to handle multiple virii in kavd response
        // originally submitted by cahya <littlecahya@yahoo.de>
        while (reply[0] != '2' && rc != 0) {
            reply.removeWhiteSpace();
            lastvirusname = lastvirusname + " " + reply.after("322-").before(" ");
            try {
                rc = stripedsocks.getLine(buff, 4096, o.content_scanner_timeout);
            } catch (std::exception &e) {
                delete[] buff;
                stripedsocks.close();
                logger_error("Error reading kavdscan socket");
                return E2CS_SCANERROR;
            }
            reply = buff;
            logger_debug("Got from kavdscan:", reply);
        }
        logger_error("lastvirusname: ", lastvirusname);
        delete[] buff;
        stripedsocks.close();

        // format: 322 nastyvirus blah
        blockFile(NULL, NULL, checkme);
        return E2CS_INFECTED;
    }
    delete[] buff;
    stripedsocks.close();
    // must be an error then
    lastmessage = reply;
    return E2CS_SCANERROR;
}
