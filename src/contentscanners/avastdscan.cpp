// AvastD content scanning plugin

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

#include <sys/stat.h>
#include <unistd.h>

// GLOBALS

extern OptionContainer o;

// DECLARATIONS

// class name is relevant!
class avastdinstance : public CSPlugin
{
    public:
    avastdinstance(ConfigVar &definition)
        : CSPlugin(definition), archivewarn(false){};

    // we are not replacing scanTest or scanMemory
    // but for scanFile and the default scanMemory to work, we need a working scanFile implementation
    int scanFile(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, FOptionContainer* &foc,
        const char *ip, const char *filename, NaughtyFilter *checkme,
        const String *disposition, const String *mimetype);

    int init(void *args);

    private:
    // AvastD UNIX domain socket path
    String udspath;
    // Whether or not to just issue a warning on archive limit/encryption warnings
    bool archivewarn;

    static String encode(const String &Str);
    // Set avastd protocol for new deamon version
    String avastprotocol;
    String scanreturncode;
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

CSPlugin *avastdcreate(ConfigVar &definition)
{
    return new avastdinstance(definition);
}

// end of Class factory

// initialise the plugin
int avastdinstance::init(void *args)
{
    int rc;
    if ((rc = CSPlugin::init(args)) != E2CS_OK)
        return rc;

    // read in AvastD UNIX domain socket path
    udspath = cv["avastdudsfile"];
    if (udspath.length() < 3) {
        logger_error("Error reading avastdudsfile option.", udspath);
        return E2CS_ERROR;
        // it would be far better to do a test connection to the file but
        // could not be arsed for now
    }

    archivewarn = cv["archivewarn"] == "on";
    logger_debug("avastd configuration: archivewarn = ", archivewarn);
    avastprotocol = cv["avastprotocol"];
    if (avastprotocol.length() < 3) {
        avastprotocol = "avast4";
        logger_error("avasd configuration missing avastprotocol: use ", avastprotocol);
    }
    if (avastprotocol.compare("avast4") != 0 && avastprotocol.compare("avast2014") != 0) {
        logger_error("Error reading avastprotocol option.");
        return E2CS_ERROR;
    }
    logger_debug("avastd configuration: avastprotocol = ", avastprotocol);

    // set some parameter by avastd protocol version
    if (avastprotocol.compare("avast4") == 0) {
        scanreturncode = "200 ";
    } else
        scanreturncode = "210 ";
    return E2CS_OK;
}

// no need to replace the inheritied scanMemory() which just calls scanFile()
// there is no capability to scan memory with avastdscan as we pass it
// a file name to scan.  So we save the memory to disk and pass that.
// Then delete the temp file.
int avastdinstance::scanFile(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user,
    FOptionContainer* &foc, const char *ip, const char *filename, NaughtyFilter *checkme,
    const String *disposition, const String *mimetype)
{
    lastmessage = lastvirusname = String();
    // mkstemp seems to only set owner permissions, so our AV daemon won't be
    // able to read the file, unless it's running as the same user as us. that's
    // not usually very convenient. so instead, just allow group read on the
    // file, and tell users to make sure the daemongroup option is friendly to
    // the AV daemon's group membership.
    // TODO? chmod can error out with EINTR, we may wish to ignore this
    if (chmod(filename, S_IRGRP | S_IRUSR) != 0) {
        lastmessage = "Error giving AvastD read access to temp file";
        logger_error("Could not change file ownership to give AvastD read access: ", strerror(errno));
        return E2CS_SCANERROR;
    };

    UDSocket stripedsocks;
    if (stripedsocks.getFD() < 0) {
        lastmessage = "Error opening socket to talk to AvastD";
        logger_error("Error creating socket for talking to AvastD");
        return E2CS_SCANERROR;
    }
    if (stripedsocks.connect(udspath.toCharArray()) < 0) {
        lastmessage = "Error connecting to AvastD socket";
        logger_error("Error connecting to AvastD socket");
        return E2CS_SCANERROR;
    }

    char buffer[4096];
    int rc;
    bool infected = false;
    bool warning = false;
    bool truncated = false;

    try {
        // After connecting, the daemon sends the following welcome message:
        // 220 Welcome to avast! Virus scanning daemon x.x (VPS yy-yy dd.mm.yyyy)
        rc = stripedsocks.getLine(buffer, sizeof(buffer), o.content_scanner_timeout);
        logger_debug("Got from avastd: ", encode(buffer));

        if (strncmp(buffer, "220 ", 4) != 0) {
            lastmessage = "Unexpected reply during AvastD handshake: ";
            String ebuffer(encode(buffer));
            lastmessage += ebuffer;
            logger_error(lastmessage);
            return E2CS_SCANERROR;
        }
        // Syntax:
        // SCAN FileName (with some escaping)
        String command("SCAN ");
        command += encode(filename);
        command += "\r\n";
        logger_debug("avastd command: ", encode(command));
        stripedsocks.writeString(command.toCharArray());

        // Possible return codes:
        // One of the following:
        //         501 Syntax error in arguments
        //         451 Engine error %d
        //         200 OK

        rc = stripedsocks.getLine(buffer, sizeof(buffer), o.content_scanner_timeout);
        logger_debug("Got from avastd: ", encode(buffer));

        if (strncmp(buffer, scanreturncode.toCharArray(), 4) != 0) {
            lastmessage = "Unexpected reply to scan command: ";
            String ebuffer(encode(buffer));
            lastmessage += ebuffer;
            logger_error(lastmessage);
            return E2CS_SCANERROR;
        }

        // Scan response format:
        // avast4: Filepath\t[Status]\tMoreInfo
        // avast2014: SCAN\sFilepath\t[Statos]\tMoreInfo\tVirusName
        // where:
        //         \t is ASCII character 9 (tab)
        //         FilePath is full path to the scanned file
        //         [Status] is one of the following values
        //         [+] - scan succeeded, the file is clean
        //         [L] - scan succeeded, the file is infected, for more info see
        // Following these lines there is a blank line which signals the end of data
        // transter from the daemon side.

        for (rc = stripedsocks.getLine(buffer, sizeof(buffer), o.content_scanner_timeout, false, NULL, &truncated);
            rc > 0 && !truncated && buffer[0] != '\r';

            rc = stripedsocks.getLine(buffer, sizeof(buffer), o.content_scanner_timeout, false, NULL, &truncated)) {
            logger_debug("Got from avastd: ", encode(buffer));

            // If a line can't fit in our buffer, we're probably dealing with a zip bomb or
            // something similarly nasty. Let's consider it an error, whatever archivewarn says.
            if (buffer[rc - 1] != '\r') {
                lastmessage = "Error whilst reading AvastD socket: can't fit line in buffer.";
                logger_error(lastmessage);
                return E2CS_SCANERROR;
            }

            // We're looking for this kind of string: ^[^\t]*\t\[.\](\t.*)?\r$
            char *result = strchr(buffer, '\t');
            if (strncmp(buffer, "200 ", 4) == 0 && avastprotocol.compare("avast2014") == 0) {
                logger_debug("ignore 200 SCAN OK and exit loop");
                break;
            } else {
                if ((avastprotocol.compare("avast4") == 0 && (result == NULL || result[1] != '[' || result[1] == '\0' || result[3] != ']' || (result[4] != '\t' && result[4] != '\r'))) || (avastprotocol.compare("avast2014") == 0 && (result == NULL || result[1] != '[' || result[1] == '\0' || result[3] != ']'))) {
                    lastmessage = "Unexpected reply in scan results: ";
                    String ebuffer(encode(buffer));
                    lastmessage += ebuffer;
                    logger_error(lastmessage);
                    return E2CS_SCANERROR;
                }
                *result = '\0';
                result += 5;
                switch (result[-3]) {
                case '+':
                    // Clean!
                    logger_debug("avastd result: ", encode(buffer) "\tclean!");
                    break;

                case 'L':
                    // Infected!
                    logger_debug("avastd result: ", encode(buffer), "\tinfected with ", result);
                    if (!lastvirusname.empty())
                        lastvirusname += " ";
                    {
                        char *r = strchr(result, '\r');
                        lastvirusname += r == NULL ? result : String(result, r - result);
                    }
                    infected = true;
                    break;

                default:
                    // Can't interpret result.
                    logger_debug("avastd result: ", encode(buffer), "\tcan't analyze (", result, ")" );
                    if (!lastvirusname.empty())
                        lastvirusname += " ";
                    lastvirusname += "Encrypted";
                    warning = true;
                    break;
                }
            }
        }
    } catch (std::exception &e) {
        lastmessage = "Exception whilst reading AvastD socket: ";
        lastmessage += e.what();
        logger_error(lastmessage);
        return E2CS_SCANERROR;
    }
    logger_debug("avastd final result: infected: ", infected, "\twarning: ", warning, "\tlastvirusname: ", lastvirusname, "\ttruncated: ", truncated);

    // Socket unexpectedly closed.
    if (rc == 0 || truncated || (avastprotocol.compare("avast4") == 0 && buffer[0] != '\r')) {
        lastmessage = "Error whilst reading AvastD socket: truncated data.";
        logger_error(lastmessage);
        return E2CS_SCANERROR;
    }

    if (infected || (warning && archivewarn)) {
        blockFile(NULL, NULL, checkme);
        return E2CS_INFECTED;
    }
    return E2CS_CLEAN;
}

String avastdinstance::encode(const String &Str)
{
    char Enc[Str.length() * 2];
    char *p = Enc;

    for (String::const_iterator i = Str.begin(); i != Str.end(); ++i)
        switch (*i) {
        case '\t':
            *(p++) = '\\';
            *(p++) = 't';
            break;
        case '\n':
            *(p++) = '\\';
            *(p++) = 'n';
            break;
        case '\r':
            *(p++) = '\\';
            *(p++) = 'r';
            break;
        case '\\':
            *(p++) = '\\';
            *(p++) = '\\';
            break;
        case '\0':
            // This shouldn't happen.
            logger_debug("Warning: '\\0' found in filename.");
            *(p++) = '\\';
            *(p++) = '0';
            break;
        default:
            *(p++) = *i;
            break;
        }

    // No need to allocate new memory if no escapes were inserted.
    if (p - Enc == Str.length())
        return String(Str);
    else
        return String(Enc, p - Enc);
}
