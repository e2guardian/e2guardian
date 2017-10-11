// AvastD content scanning plugin

// For all support, instructions and copyright go to:
// http://e2guardian.org/
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
#include <sys/stat.h>
#include <unistd.h>

// GLOBALS

extern OptionContainer o;
extern bool is_daemonised;

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
    if ((rc = CSPlugin::init(args)) != DGCS_OK)
        return rc;

    // read in AvastD UNIX domain socket path
    udspath = cv["avastdudsfile"];
    if (udspath.length() < 3) {
        if (!is_daemonised)
            std::cerr << "Error reading avastdudsfile option." << udspath << std::endl;
        syslog(LOG_ERR, "Error reading avastdudsfile option.");
        return DGCS_ERROR;
        // it would be far better to do a test connection to the file but
        // could not be arsed for now
    }

    archivewarn = cv["archivewarn"] == "on";
#ifdef DGDEBUG
    std::cout << "avastd configuration: archivewarn = " << archivewarn << std::endl;
#endif
    avastprotocol = cv["avastprotocol"];
    if (avastprotocol.length() < 3) {
        avastprotocol = "avast4";
        syslog(LOG_ERR, "avasd configuration missing avastprotocol: use avast4");
#ifdef DGDEBUG
        std::cout << "avastd configuration: set default paramater = " << avastprotocol << std::endl;
#endif
    }
    if (avastprotocol.compare("avast4") != 0 && avastprotocol.compare("avast2014") != 0) {
        if (!is_daemonised)
            std::cerr << "Error reading avastprotocol option." << std::endl;
        syslog(LOG_ERR, "Error reading avastprotocol option.");
        return DGCS_ERROR;
    }
#ifdef DGDEBUG
    std::cout << "avastd configuration: avastprotocol = " << avastprotocol << std::endl;
#endif
    // set some parameter by avastd protocol version
    if (avastprotocol.compare("avast4") == 0) {
        scanreturncode = "200 ";
    } else
        scanreturncode = "210 ";
    return DGCS_OK;
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
        syslog(LOG_ERR, "Could not change file ownership to give AvastD read access: %s", strerror(errno));
        return DGCS_SCANERROR;
    };

    UDSocket stripedsocks;
    if (stripedsocks.getFD() < 0) {
        lastmessage = "Error opening socket to talk to AvastD";
        syslog(LOG_ERR, "Error creating socket for talking to AvastD");
        return DGCS_SCANERROR;
    }
    if (stripedsocks.connect(udspath.toCharArray()) < 0) {
        lastmessage = "Error connecting to AvastD socket";
        syslog(LOG_ERR, "Error connecting to AvastD socket");
        return DGCS_SCANERROR;
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
#ifdef DGDEBUG
        std::cout << "Got from avastd: " << encode(buffer) << std::endl;
#endif
        if (strncmp(buffer, "220 ", 4) != 0) {
            lastmessage = "Unexpected reply during AvastD handshake: ";
            String ebuffer(encode(buffer));
            lastmessage += ebuffer;
            syslog(LOG_ERR, "Unexpected reply during AvastD handshake: %s", ebuffer.toCharArray());
            return DGCS_SCANERROR;
        }
        // Syntax:
        // SCAN FileName (with some escaping)
        String command("SCAN ");
        command += encode(filename);
        command += "\r\n";
#ifdef DGDEBUG
        std::cerr << "avastd command: " << encode(command) << std::endl;
#endif
        stripedsocks.writeString(command.toCharArray());

        // Possible return codes:
        // One of the following:
        //         501 Syntax error in arguments
        //         451 Engine error %d
        //         200 OK

        rc = stripedsocks.getLine(buffer, sizeof(buffer), o.content_scanner_timeout);
#ifdef DGDEBUG
        std::cout << "Got from avastd: " << encode(buffer) << std::endl;
#endif
        if (strncmp(buffer, scanreturncode.toCharArray(), 4) != 0) {
            lastmessage = "Unexpected reply to scan command: ";
            String ebuffer(encode(buffer));
            lastmessage += ebuffer;
            syslog(LOG_ERR, "Unexpected reply to scan command: %s", ebuffer.toCharArray());
            return DGCS_SCANERROR;
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
#ifdef DGDEBUG
            std::cout << "Got from avastd: " << encode(buffer) << std::endl;
#endif
            // If a line can't fit in our buffer, we're probably dealing with a zip bomb or
            // something similarly nasty. Let's consider it an error, whatever archivewarn says.
            if (buffer[rc - 1] != '\r') {
                lastmessage = "Error whilst reading AvastD socket: can't fit line in buffer.";
                syslog(LOG_ERR, "Error whilst reading AvastD socket: can't fit line in buffer.");
                return DGCS_SCANERROR;
            }

            // We're looking for this kind of string: ^[^\t]*\t\[.\](\t.*)?\r$
            char *result = strchr(buffer, '\t');
            if (strncmp(buffer, "200 ", 4) == 0 && avastprotocol.compare("avast2014") == 0) {
#ifdef DGDEBUG
                std::cout << "ignore 200 SCAN OK and exit loop" << std::endl;
#endif
                break;
            } else {
                if ((avastprotocol.compare("avast4") == 0 && (result == NULL || result[1] != '[' || result[1] == '\0' || result[3] != ']' || (result[4] != '\t' && result[4] != '\r'))) || (avastprotocol.compare("avast2014") == 0 && (result == NULL || result[1] != '[' || result[1] == '\0' || result[3] != ']'))) {
                    lastmessage = "Unexpected reply in scan results: ";
                    String ebuffer(encode(buffer));
                    lastmessage += ebuffer;
                    syslog(LOG_ERR, "Unexpected reply in scan results: %s", ebuffer.toCharArray());
                    return DGCS_SCANERROR;
                }
                *result = '\0';
                result += 5;
                switch (result[-3]) {
                case '+':
// Clean!
#ifdef DGDEBUG
                    std::cout << "avastd result: " << encode(buffer) << "\tclean!" << std::endl;
#endif
                    break;

                case 'L':
// Infected!
#ifdef DGDEBUG
                    std::cout << "avastd result: " << encode(buffer) << "\tinfected with " << result << std::endl;
#endif
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
#ifdef DGDEBUG
                    std::cout << "avastd result: " << encode(buffer) << "\tcan't analyze (" << result << ")" << std::endl;
#endif
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
        syslog(LOG_ERR, "Exception whilst reading AvastD socket: %s", e.what());
        return DGCS_SCANERROR;
    }
#ifdef DGDEBUG
    std::cout << "avastd final result: infected: " << infected << "\twarning: " << warning << "\tlastvirusname: " << lastvirusname << "\ttruncated: " << truncated << std::endl;
#endif

    // Socket unexpectedly closed.
    if (rc == 0 || truncated || (avastprotocol.compare("avast4") == 0 && buffer[0] != '\r')) {
        lastmessage = "Error whilst reading AvastD socket: truncated data.";
        syslog(LOG_ERR, "Error whilst reading AvastD socket: truncated data.");
        return DGCS_SCANERROR;
    }

    if (infected || (warning && archivewarn)) {
        blockFile(NULL, NULL, checkme);
        return DGCS_INFECTED;
    }
    return DGCS_CLEAN;
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
#ifdef DGDEBUG
        case '\0':
            // This shouldn't happen.
            std::cerr << "Warning: '\\0' found in filename." << std::endl;
            *(p++) = '\\';
            *(p++) = '0';
            break;
#endif
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
