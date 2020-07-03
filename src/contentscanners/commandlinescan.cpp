// Command line content scanning plugin

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
#include "../RegExp.hpp"
#include "../Logger.hpp"

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <list>
#include <cstdio>
#include <cstdlib>

// GLOBALS

extern OptionContainer o;

// IMPLEMENTATION

// class name is relevant
class commandlineinstance : public CSPlugin
{
    public:
    commandlineinstance(ConfigVar &definition)
        : CSPlugin(definition), usevirusregexp(false), submatch(0), arguments(NULL), numarguments(0), infectedcodes(NULL), numinfectedcodes(0), cleancodes(NULL), numcleancodes(0), defaultresult(-1){};
    int scanFile(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, FOptionContainer* &foc ,
        const char *ip, const char *filename, NaughtyFilter *checkme,
        const String *disposition, const String *mimetype);

    int init(void *args);

    ~commandlineinstance()
    {
        delete[] infectedcodes;
        delete[] cleancodes;
        for (int i = 0; i < numarguments; i++)
            delete arguments[i];
        delete[] arguments;
    };

    private:
    // regular expression for finding virus names in program output
    RegExp virusregexp;
    RegResult virusregexpres;
    // whether or not the above is in use
    bool usevirusregexp;
    // which sub-match to take from the match
    int submatch;

    // path to command-line scanning program (+ initial arguments)
    String progname;
    // argument array (the above must be split on space for passing to exec)
    char **arguments;
    int numarguments;

    // return code(s) for infected files
    int *infectedcodes;
    int numinfectedcodes;
    // return code(s) for uninfected files
    int *cleancodes;
    int numcleancodes;

    // optional default result - can be used to e.g. define only cleancodes,
    // and have everything else default to infected.
    int defaultresult;
};

// class factory code *MUST* be included in every plugin

CSPlugin *commandlinecreate(ConfigVar &definition)
{
    return new commandlineinstance(definition);
}

// end of Class factory

// initialise plugin
int commandlineinstance::init(void *args)
{
    int rc;
    if ((rc = CSPlugin::init(args)) != E2CS_OK)
        return rc;

    // read in program name
    progname = cv["progname"];
    if (progname.length() == 0) {
        logger_error("Command-line scanner: No program specified");
        return E2CS_ERROR;
    }

    // split into an argument array
    std::list<std::string> temparguments;
    char *tempprogname = new char[progname.length() + 1];
    tempprogname[progname.length()] = '\0';
    strncpy(tempprogname, progname.c_str(), progname.length());
    char *result = strtok(tempprogname, " ");
    while (result) {
        temparguments.push_back(std::string(result));
        result = strtok(NULL, " ");
    }
    delete[] tempprogname;
    for (int i = 0; i < numarguments; i++)
        delete arguments[i];
    delete[] arguments;
    numarguments = temparguments.size();
    arguments = new char *[numarguments + 2];
    arguments[numarguments + 1] = NULL;
    int count = 0;
    for (std::list<std::string>::iterator i = temparguments.begin(); i != temparguments.end(); i++) {
        char *newthing = new char[i->length()];
        strcpy(newthing, i->c_str());
        arguments[count++] = newthing;
    }
    progname = cv["progname"];

#ifdef E2DEBUG
    std::cerr << thread_id << "Program and arguments: ";
    for (int i = 0; i < numarguments; i++) {
        std::cerr << thread_id << arguments[i] << " ";
    }
    std::cerr << thread_id << std::endl;
#endif

    // read in virus name regular expression
    String ucvirusregexp(cv["virusregexp"]);
    if (ucvirusregexp.length()) {
        usevirusregexp = true;
        if (!virusregexp.comp(ucvirusregexp.toCharArray())) {
            logger_error("Command-line scanner: Could not compile regular expression for extracting virus names");
            return E2CS_ERROR;
        }
        String ssubmatch(cv["submatch"]);
        if (ssubmatch.length())
            submatch = ssubmatch.toInteger();
    }

    // read in the lists of good and bad program return codes
    String sinfectedcodes(cv["infectedcodes"]);
    String scleancodes(cv["cleancodes"]);
    std::list<int> tempinfectedcodes;
    std::list<int> tempcleancodes;
    char *tempcodes = new char[sinfectedcodes.length() + 1];
    tempcodes[sinfectedcodes.length()] = '\0';
    strncpy(tempcodes, sinfectedcodes.c_str(), sinfectedcodes.length());
    result = strtok(tempcodes, ",");
    logger_debug("Infected file return codes: ");
    while (result) {
        tempinfectedcodes.push_back(atoi(result));
        logger_debug(tempinfectedcodes.back() );
        result = strtok(NULL, ",");
    }
    delete[] tempcodes;
    tempcodes = new char[scleancodes.length() + 1];
    tempcodes[scleancodes.length()] = '\0';
    strncpy(tempcodes, scleancodes.c_str(), scleancodes.length());
    result = strtok(tempcodes, ",");
    
    logger_debug("Clean file return codes: ");
    while (result) {
        tempcleancodes.push_back(atoi(result));
        logger_debug(tempcleancodes.back());
        result = strtok(NULL, ",");
    }
    delete[] tempcodes;

    // we need at least one of our three mechanisms (cleancodes, infectedcodes and virus names)
    // to be defined in order to make a decision about the nature of a scanning result.
    numcleancodes = tempcleancodes.size();
    numinfectedcodes = tempinfectedcodes.size();
    if (!(usevirusregexp || numcleancodes || numinfectedcodes)) {
        logger_error("Command-line scanner requires some mechanism for interpreting results. Please define cleancodes, infectedcodes, and/or a virusregexp.");
        return E2CS_ERROR;
    }

    // Copy return code lists out into static arrays
    delete[] infectedcodes;
    delete[] cleancodes;
    infectedcodes = new int[numinfectedcodes];
    cleancodes = new int[numcleancodes];
    count = 0;
    for (std::list<int>::iterator i = tempinfectedcodes.begin(); i != tempinfectedcodes.end(); i++)
        infectedcodes[count++] = *i;
    count = 0;
    for (std::list<int>::iterator i = tempcleancodes.begin(); i != tempcleancodes.end(); i++)
        cleancodes[count++] = *i;

    // read in default result type
    String sdefaultresult(cv["defaultresult"]);
    if (sdefaultresult.length()) {
        if (sdefaultresult == "clean") {
            defaultresult = 1;
        } else if (sdefaultresult == "infected") {
            defaultresult = 0;
        } else {
            logger_error("Command-line scanner: Default result value not understood");
            return E2CS_WARNING;
        }
    }

    return E2CS_OK;
}

// no need to replace the inheritied scanMemory() which just calls scanFile()
// there is no capability to scan memory with commandlinescan as we pass it
// a file name to scan.  So we save the memory to disk and pass that.
// Then delete the temp file.
// TODO Allow for placeholders in command line for inserting content-disposition & content-type?
int commandlineinstance::scanFile(HTTPHeader *requestheader, HTTPHeader *docheader, const char *user, FOptionContainer* &foc ,
    const char *ip, const char *filename, NaughtyFilter *checkme, const String *disposition, const String *mimetype)
{
    // create socket pairs for child (scanner) process's stdout & stderr
    int scannerstdout[2];
    int scannerstderr[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, scannerstdout) == -1) {
        lastmessage = "Cannot create sockets for communicating with scanner";
        logger_error(lastmessage, " ", strerror(errno) );
        return E2CS_SCANERROR;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, scannerstderr) == -1) {
        lastmessage = "Cannot create sockets for communicating with scanner" ;
        logger_error(lastmessage, " ", strerror(errno) );
        return E2CS_SCANERROR;
    }
    int f = fork();
    if (f == 0) {
        logger_debug("Running: ", progname, " ", filename);
        // close read ends of sockets
        close(scannerstdout[0]);
        close(scannerstderr[0]);
        // bind stdout & stderr
        dup2(scannerstdout[1], 1);
        dup2(scannerstderr[1], 2);
        // execute scanner
        arguments[numarguments] = (char *)filename;
        execv(arguments[0], arguments);
        // if we get here, an error occurred!
        logger_error("Cannot exec command-line scanner (command ", progname, "  ",filename, "): ", strerror(errno));
        _exit(255);
    } else if (f == -1) {
        lastmessage = "Cannot launch scanner";
        logger_error("Cannot fork to launch command-line scanner (command ", progname, "  ",filename, "): ", strerror(errno));
        return E2CS_SCANERROR;
    }

    // close write ends of sockets
    close(scannerstdout[1]);
    close(scannerstderr[1]);

    char buff[8192];
    std::string result;
    FILE *readme = fdopen(scannerstdout[0], "r");
    while (fgets(buff, 8192, readme) != NULL) {
#ifndef E2DEBUG
        if (usevirusregexp)
#endif
            result += buff;
    }
    fclose(readme);
    readme = fdopen(scannerstderr[0], "r");
    while (fgets(buff, 8192, readme) != NULL) {
#ifndef E2DEBUG
        if (usevirusregexp)
#endif
            result += buff;
    }
    fclose(readme);

    // close read ends too now
    close(scannerstdout[0]);
    close(scannerstderr[0]);

    // wait for scanner to quit & retrieve exit status
    int returncode;
    returncode = WEXITSTATUS(returncode);

    if (waitpid(f, &returncode, 0) == -1) {
        lastmessage = "Cannot get scanner return code";
        logger_error(lastmessage, " ", strerror(errno));
        return E2CS_SCANERROR;
    }

    logger_debug("Scanner result: ", (result), "Code: ", returncode);
    if (returncode == 255) {
        lastmessage = "Cannot get scanner return code";
        logger_error("Cannot get command-line scanner return code: scanner exec failed");
        return E2CS_SCANERROR;
    }

    lastvirusname = "Unknown";

    if (usevirusregexp) {
        virusregexp.match(result.c_str(), virusregexpres);
        if (virusregexpres.matched()) {
            lastvirusname = virusregexpres.result(submatch);
            blockFile(NULL, NULL, checkme);
            return E2CS_INFECTED;
        }
    }

    if (cleancodes) {
        for (int i = 0; i < numcleancodes; i++) {
            if (returncode == cleancodes[i])
                return E2CS_CLEAN;
        }
    }

    if (infectedcodes) {
        for (int i = 0; i < numinfectedcodes; i++) {
            if (returncode == infectedcodes[i]) {
                blockFile(NULL, NULL, checkme);
                return E2CS_INFECTED;
            }
        }
    }

    if (defaultresult == 1)
        return E2CS_CLEAN;
    else if (defaultresult == 0) {
        blockFile(NULL, NULL, checkme);
        return E2CS_INFECTED;
    }

    if (returncode != 0)
        return E2CS_SCANERROR;
    return 0;
}
