// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "FatController.hpp"
#include "SysV.hpp"
#include "Queue.hpp"
#include "Logger.hpp"
#include "LoggerConfigurator.hpp"

#include <cstdlib>
#include <iostream>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <cerrno>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <fcntl.h>
#include <locale.h>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/times.h>
#include <sys/resource.h>

#ifdef __BENCHMARK
#include <sys/times.h>
#include "NaughtyFilter.hpp"
#endif

// GLOBALS

OptionContainer o;
thread_local std::string thread_id;
std::atomic<bool> g_is_starting;

LoggerConfigurator loggerConfig(&e2logger);
bool is_daemonised;

// regexp used during URL decoding by HTTPHeader
// we want it compiled once, not every time it's used, so do so on startup
RegExp urldecode_re;

#ifdef HAVE_PCRE
// regexes used for embedded URL extraction by NaughtyFilter
RegExp absurl_re, relurl_re;
#endif

// DECLARATIONS
int readCommandlineOptions(int &ret, int argc, char *argv[]);
int startDaemon();
int runBenchmarks();
bool check_enough_filedescriptors();
void prepareRegExp();

#define E2_LOAD   1
#define E2_EXIT   2

// IMPLEMENTATION

int main(int argc,char *argv[])
{
    g_is_starting = true;
    thread_id = "";
    int ret = 0;

    o.config.prog_name = PACKAGE;
    o.config.configfile = __CONFFILE;

    srand(time(NULL));

    // Set current locale for proper character conversion
    setlocale(LC_ALL, "");

    e2logger.setSyslogName(o.config.prog_name);

//    E2LOGGER_info("Start ", prog_name );  // No we are not starting here - we may be stopping, reloading etc

#ifdef DEBUG_LOW
    e2logger.enable(LoggerSource::debug);
    DEBUG_debug("Running in debug_low mode...");
#endif

    DEBUG_trace("read CommandLineOptions");
    int rc = readCommandlineOptions(ret, argc, argv);
    if (rc == E2_EXIT) return ret;
    
    DEBUG_trace("read Configfile: ", o.config.configfile);
    if (!o.read_config(o.config.configfile)) {
        E2LOGGER_error( "Error parsing the e2guardian.conf file or other e2guardian configuration files");
        exit(1); // OptionContainer class had an error reading the conf or other files so exit with error
    }


    if (o.config.total_block_list) {
        if (o.readinStdin()) {
            DEBUG_debug("Total block lists read OK from stdin.");
        } 
        else 
        {
            E2LOGGER_error("Error on reading total_block_list");
        }
    }

    DEBUG_trace("create Lists");
    if (!o.createLists(0))  {
        E2LOGGER_error("Error reading filter group conf file(s).");
        return 1;
    }

    prepareRegExp();

    return startDaemon();

}


int readCommandlineOptions(int &ret, int argc, char *argv[])  // returns E2_EXIT or E2_LOAD
{
    bool needreset = false;
    std::string debugoptions;

    DEBUG_trace("parse Options");
    for (int i = 1; i < argc; i++) {  // first check for config file
        if (argv[i][0] == '-') {
            for (unsigned int j = 1; j < strlen(argv[i]); j++) {
                char option = argv[i][j];
                bool dobreak = false;
                switch (option) {
                    case 'c':
                        if ((i + 1) < argc) {
                            o.config.configfile = argv[i + 1];
                            i++;
                            dobreak = true;
                        } else {
                            std::cerr << "No config file specified!" << std::endl;
                            ret = 1;
                            return E2_EXIT;
                        }
                        break;
                }
                if (dobreak) break;
            }
        }
    }

    for (int i = 1; i < argc; i++) {    // then rest of args
        bool skip_next = false;
        if (argv[i][0] == '-') {
            for (unsigned int j = 1; j < strlen(argv[i]); j++) {
                char option = argv[i][j];
                bool dobreak = false;
                switch (option) {
                case 'q':
                    o.read_config(o.config.configfile, false);
                    ret = sysv_kill(o.proc.pid_filename,true);
                    return E2_EXIT;
                case 'Q':
                    o.read_config(o.config.configfile, false);
                    sysv_kill(o.proc.pid_filename, false);
                    // give the old process time to die
                    while (sysv_amirunning(o.proc.pid_filename))
                        sleep(1);
                    unlink(o.proc.pid_filename.c_str());
                    // remember to reset config before continuing
                    needreset = true;
                    break;
                case 's':
                    o.read_config(o.config.configfile, false);
                    ret = sysv_showpid(o.proc.pid_filename);
                    return E2_EXIT;
                case 'r':
                case 'g':
                    o.read_config(o.config.configfile, false);
                    ret = sysv_hup(o.proc.pid_filename);
                    return E2_EXIT;
                case 't':
                    o.read_config(o.config.configfile, false);
                    ret = sysv_usr1(o.proc.pid_filename);
                        return E2_EXIT;
                case 'v':
                    std::cout << "e2guardian " << PACKAGE_VERSION << std::endl
                              << std::endl
                              << "Built with: " << E2_CONFIGURE_OPTIONS << std::endl;
                    ret = 0;
                        return E2_EXIT;
                case 'N':
                    o.proc.no_daemon = true;
                    break;
                case 'c':   // already processed this - so skip
                    skip_next = true;
                    break;
                case 'i':
                    o.config.total_block_list = true;
                    break;
                case 'd':
                    if ((i + 1) < argc) {
                        debugoptions = argv[i+1];
                        i++;
                        dobreak = true;
                    };
                    break;

                case 'h':
                default:
                    std::cout << "Usage: " << argv[0] << " [-c ConfigFileName|-v|-h|-N|-q|-Q|-s|-r|-g|-i] [-d debuglevel]" << std::endl;
                    std::cout << "  -v gives the version number and build options." << std::endl;
                    std::cout << "  -h gives this message." << std::endl;
                    std::cout << "  -c allows you to specify a different configuration file location." << std::endl;
                    std::cout << "  -N Do not go into the background." << std::endl;
                    std::cout << "  -q causes e2guardian to kill any running copy." << std::endl;
                    std::cout << "  -Q kill any running copy AND start a new one with current options." << std::endl;
                    std::cout << "  -s shows the parent process PID and exits." << std::endl;
                    std::cout << "  -r reloads lists and group config files by issuing a HUP," << std::endl;
                    std::cout << "     but this does not reset the httpworkers option (amongst others)." << std::endl;
                    std::cout << "  -g  same as -r  (Issues a HUP)" << std::endl;
                    std::cout << "  -t  rotate logs (Issues a USR1)" << std::endl;
                    std::cout << "  -d  allows you to specify a debuglevel" << std::endl;
                    std::cout << "  -i read lists from stdin" << std::endl;
                    ret = 0;
                    return E2_EXIT;
                }
                if (dobreak)
                    break; // skip to the next argument
            }
        }
        if(skip_next) i++;
    }

    if (needreset) {
        DEBUG_trace("reset Options");
        o.reset();
    }

    if (!debugoptions.empty()) {
        loggerConfig.debuglevel(debugoptions);
    }
    
    return E2_LOAD;

}    


int startDaemon()
{
    DEBUG_trace("prepare Start");
    if (sysv_amirunning(o.proc.pid_filename)) {
        E2LOGGER_error("I seem to be running already!");
        return 1; // can't have two copies running!!
    }

    if (!check_enough_filedescriptors()) return 1;
    if (!o.proc.find_user_ids()) return 1;
    if (!o.proc.become_proxy_user()) return 1;

    DEBUG_trace("Starting Main loop");
    while (true) {
        int rc = fc_controlit();
        // its a little messy, but I wanted to split
        // all the ground work and non-daemon stuff
        // away from the daemon class
        // However the line is not so fine.
        // fc_controlit never returns 2 ??!  KDG 2020-09-25
        if (rc == 2) {

            // In order to re-read the conf files
            // we need to become root user again
            if (!o.proc.become_root_user()) return 1;

            DEBUG_trace("About to re-read conf file.");
            o.reset();
            if (!o.read_config(o.config.configfile, true)) {
                // OptionContainer class had an error reading the conf or
                // other files so exit with errora
                E2LOGGER_error("Error re-parsing the e2guardian.conf file or other e2guardian configuration files");
                return 1;
            }
            DEBUG_trace("conf file read.");

            while (waitpid(-1, NULL, WNOHANG) > 0) {
            } // mop up defunts

            // become low priv again
            if (!o.proc.become_proxy_user()) return 1;
            continue;
        }

        if (o.proc.is_daemonised)
        	return 0; // exit without error
        if (rc > 0) {
            E2LOGGER_error("Exiting with error");
            return rc; // exit returning the error number
        }

    }

}

void prepareRegExp()
{
    urldecode_re.comp("%[0-9a-fA-F][0-9a-fA-F]"); // regexp for url decoding

#ifdef HAVE_PCRE
    // todo: these only work with PCRE enabled (non-greedy matching).
    // change them, or make them a feature for which you need PCRE?
    absurl_re.comp("[\"'](http|ftp)://.*?[\"']"); // find absolute URLs in quotes
    relurl_re.comp("(href|src)\\s*=\\s*[\"'].*?[\"']"); // find relative URLs in quotes
#endif

}

bool check_enough_filedescriptors()
{
    // calc the number of listening processes
    int no_listen_fds;
//    if (o.net.map_ports_to_ips) {
//        no_listen_fds = o.net.filter_ip.size();
//    } else {
        no_listen_fds = o.net.filter_ports.size() * o.net.filter_ip.size();
        // TODO: Add in icap httptrans and httpproxy ports
//    }

    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        E2LOGGER_error( "getrlimit call returned error: ", errno);
        return false;
    }

    // enough fds needed for listening_fds + logger + ipcs + stdin/out/err
    // in addition to two for each worker thread
    int max_free_fds = rlim.rlim_cur - (no_listen_fds + 6);
    int fd_needed = (o.proc.http_workers *2) + no_listen_fds + 6;

    if (((o.proc.http_workers * 2) ) > max_free_fds) {
        E2LOGGER_error("httpworkers option in e2guardian.conf has a value too high for current file id limit (", rlim.rlim_cur, ")" );
        E2LOGGER_error("httpworkers ", o.proc.http_workers,  " must not exceed 50% of ", max_free_fds);
        E2LOGGER_error("in this configuration.");
        E2LOGGER_error("Reduce httpworkers ");
        E2LOGGER_error("Or increase the filedescriptors available with ulimit -n to at least=", fd_needed);
        return false; // we can't have rampant proccesses can we?
    }

    return true;
}
