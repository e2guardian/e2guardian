// Command line content scanning plugin

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
#include "../RegExp.hpp"

#include <syslog.h>
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
extern bool is_daemonised;

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
    if ((rc = CSPlugin::init(args)) != DGCS_OK)
        return rc;

    // read in program name
    progname = cv["progname"];
    if (progname.length() == 0) {
        if (!is_daemonised)
            std::cerr << "Command-line scanner: No program specified" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
        syslog(LOG_ERR, "Command-line scanner: No program specified");
        return DGCS_ERROR;
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

#ifdef DGDEBUG
    std::cout << "Program and arguments: ";
    for (int i = 0; i < numarguments; i++) {
        std::cout << arguments[i] << " ";
    }
    std::cout << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    // read in virus name regular expression
    String ucvirusregexp(cv["virusregexp"]);
    if (ucvirusregexp.length()) {
        usevirusregexp = true;
        if (!virusregexp.comp(ucvirusregexp.toCharArray())) {
            if (!is_daemonised)
                std::cerr << "Command-line scanner: Could not compile regular expression for extracting virus names" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
            syslog(LOG_ERR, "Command-line scanner: Could not compile regular expression for extracting virus names");
            return DGCS_ERROR;
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
#ifdef DGDEBUG
    std::cout << "Infected file return codes: ";
#endif
    while (result) {
        tempinfectedcodes.push_back(atoi(result));
#ifdef DGDEBUG
        std::cout << tempinfectedcodes.back() << " ";
#endif
        result = strtok(NULL, ",");
    }
    delete[] tempcodes;
    tempcodes = new char[scleancodes.length() + 1];
    tempcodes[scleancodes.length()] = '\0';
    strncpy(tempcodes, scleancodes.c_str(), scleancodes.length());
    result = strtok(tempcodes, ",");
#ifdef DGDEBUG
    std::cout << std::endl
              << "Clean file return codes: ";
#endif
    while (result) {
        tempcleancodes.push_back(atoi(result));
#ifdef DGDEBUG
        std::cout << tempcleancodes.back() << " ";
#endif
        result = strtok(NULL, ",");
    }
    delete[] tempcodes;

    // we need at least one of our three mechanisms (cleancodes, infectedcodes and virus names)
    // to be defined in order to make a decision about the nature of a scanning result.
    numcleancodes = tempcleancodes.size();
    numinfectedcodes = tempinfectedcodes.size();
    if (!(usevirusregexp || numcleancodes || numinfectedcodes)) {
        if (!is_daemonised)
            std::cerr << "Command-line scanner requires some mechanism for interpreting results. Please define cleancodes, infectedcodes, and/or a virusregexp." << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
        syslog(LOG_ERR, "Command-line scanner requires some mechanism for interpreting results. Please define cleancodes, infectedcodes, and/or a virusregexp.");
        return DGCS_ERROR;
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
            if (!is_daemonised)
                std::cerr << "Command-line scanner: Default result value not understood" << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
            syslog(LOG_ERR, "Command-line scanner: Default result value not understood");
            return DGCS_WARNING;
        }
    }

    return DGCS_OK;
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
        // lastmessage = "Cannot create sockets for communicating with scanner";
        syslog(LOG_ERR, "Cannot open socket pair for command-line scanner's stdout: %s", strerror(errno));
        return DGCS_SCANERROR;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, scannerstderr) == -1) {
        // lastmessage = "Cannot create sockets for communicating with scanner";
        syslog(LOG_ERR, "Cannot open socket pair for command-line scanner's stderr: %s", strerror(errno));
        return DGCS_SCANERROR;
    }
    int f = fork();
    if (f == 0) {
#ifdef DGDEBUG
        std::cout << "Commandline scanner running: " << progname.toCharArray() << " " << filename << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        // close read ends of sockets
        close(scannerstdout[0]);
        close(scannerstderr[0]);
#ifdef DGDEBUG
        std::cout << "Commandline scanner running step1 close: " << progname.toCharArray() << " " << filename << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        // bind stdout & stderr
        dup2(scannerstdout[1], 1);
        dup2(scannerstderr[1], 2);
        // execute scanner
        arguments[numarguments] = (char *)filename;
#ifdef DGDEBUG
        std::cout << "Commandline scanner Running step3 execv: " << progname.toCharArray() << " " << filename << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

        execl(progname.toCharArray(), progname.toCharArray() , filename , NULL);

#ifdef DGDEBUG
        std::cout << "Commandline scanner Running step3 error: " << progname.toCharArray() << " " << filename << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        // if we get here, an error occurred!
        syslog(LOG_ERR, "Cannot exec command-line scanner (command \"%s %s\"): %s", progname.toCharArray(), filename, strerror(errno));
        _exit(255);
    } else if (f == -1) {
        // lastmessage = "Cannot launch scanner";
        syslog(LOG_ERR, "Cannot fork to launch command-line scanner (command \"%s %s\"): %s", progname.toCharArray(), filename, strerror(errno));
        return DGCS_SCANERROR;
    }

#ifdef DGDEBUG
        std::cout << "Exit fork command-line scanner : " << progname.toCharArray() << " " << filename << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif

    // close write ends of sockets
    close(scannerstdout[1]);
    close(scannerstderr[1]);

    char buff[8192];
    std::string result;
    FILE *readme1 = fdopen(scannerstdout[0], "r");
    if (NULL != readme1){
    	while (fgets(buff, 8192, readme1) != NULL) {
        	if (usevirusregexp)
            	result += buff;
    	}
    	fclose(readme1);
	close(scannerstdout[0]);
    }
    FILE *readme2 = fdopen(scannerstderr[0], "r");
    if (NULL != readme2){
   	 while (fgets(buff, 8192, readme2) != NULL) {
         	if (usevirusregexp)
                result += buff;
        }
        fclose(readme2);
    	close(scannerstderr[0]);
    }

    // wait for scanner to quit & retrieve exit status
    int returncode;
    returncode = WEXITSTATUS(returncode);

    if (waitpid(f, &returncode, 0) == -1) {
        // lastmessage = "Cannot get scanner return code";
        syslog(LOG_ERR, "Cannot get command-line scanner return code: %s", strerror(errno));
        return DGCS_SCANERROR;
    }

#ifdef DGDEBUG
    std::cout << "Commandline scanner result " << "Code: " << returncode << " " << progname.toCharArray() << " " << filename << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
    if (returncode == 255) {
        syslog(LOG_ERR, "Cannot get command-line scanner return code: scanner exec failed");
        return DGCS_SCANERROR;
    }

    if (usevirusregexp) {
        virusregexp.match(result.c_str(), virusregexpres);
        if (virusregexpres.matched()) {
#ifdef DGDEBUG
	std::cout << "Commandline scanner return DGCS_INFECTED"  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        lastvirusname = virusregexpres.result(submatch);
        blockFile(NULL, NULL, checkme);
        return DGCS_INFECTED;
        }
    }

    if (cleancodes) {
        for (int i = 0; i < numcleancodes; i++) {
            if (returncode == cleancodes[i])
#ifdef DGDEBUG
        	std::cout << "Commandline scanner return CLEAN"  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                return DGCS_CLEAN;
        }
    }

    if (infectedcodes) {
        for (int i = 0; i < numinfectedcodes; i++) {
            if (returncode == infectedcodes[i]) {
#ifdef DGDEBUG
        	std::cout << "Commandline scanner return INFECTED"  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
                blockFile(NULL, NULL, checkme);
                return DGCS_INFECTED;
            }
        }
    }

    if (defaultresult == 1){
#ifdef DGDEBUG
       	std::cout << "Commandline scanner return CLEAN - default result -"  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return DGCS_CLEAN;
    }
    else if (defaultresult == 0) {
#ifdef DGDEBUG
       	std::cout << "Commandline scanner return INFECTED - default result -"  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        blockFile(NULL, NULL, checkme);
        return DGCS_INFECTED;
    }

    if (returncode != 0){
#ifdef DGDEBUG
       	std::cout << "Commandline scanner return SCAN_ERROR"  << " Line: " << __LINE__ << " Function: " << __func__ << std::endl;
#endif
        return DGCS_SCANERROR;
    }
}
