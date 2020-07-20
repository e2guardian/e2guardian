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

LoggerConfigurator loggerConfig(&e2logger);

// regexp used during URL decoding by HTTPHeader
// we want it compiled once, not every time it's used, so do so on startup
RegExp urldecode_re;

#ifdef HAVE_PCRE
// regexes used for embedded URL extraction by NaughtyFilter
RegExp absurl_re, relurl_re;
#endif

// DECLARATIONS
int readCommandlineOptions(int argc, char *argv[]);
int runBenchmarks();
void prepareRegExp();
int startDaemon();

// program entry point
int main(int argc, char *argv[])
{

    o.config.prog_name = "e2guardian";
    o.config.configfile = __CONFFILE;

    srand(time(NULL));

    // Set current locale for proper character conversion
    setlocale(LC_ALL, "");

    e2logger.setSyslogName(o.config.prog_name);
#if E2DEBUG
    // e2logger.enable(LoggerSource::debug);
    // e2logger.enable(LoggerSource::trace);
#endif    

    e2logger_info("Start ", o.config.prog_name );
    e2logger_debug("Running in debug_mode...");

    e2logger_trace("read CommandLineOptions");
    readCommandlineOptions(argc, argv);

    e2logger_trace("read Configfile: ", o.config.configfile);
    if (!o.readConfig(o.config.configfile)) exit(-1);

    if (o.lists.read_from_stdin) {
        if (o.readinStdin())
            e2logger_debug("Total block lists read OK from stdin.");
        else
            e2logger_error("Error on reading total_block_list");
    }

    e2logger_trace("create Lists");
    if(!o.createLists(0))  {
        e2logger_error("Error reading filter group conf file(s).");
        return 1;
    }

#ifdef __BENCHMARK
    // run benchmarks instead of starting the daemon
    return runBenchmarks();
#endif

    prepareRegExp();

    return startDaemon();
}    

int startDaemon()
{
    e2logger_trace("prepare Start");
    if (sysv_amirunning(o.pid_filename)) {
        e2logger_error("I seem to be running already!");
        return 1; // can't have two copies running!!
    }

    // calc the number of listening processes
    int no_listen_fds = o.net.number_of_fds_neded();

    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        e2logger_error( "getrlimit call returned error: ", errno);
        return 1;
    }
    int max_maxchildren;
    // enough fds needed for listening_fds + logger + ipcs + stdin/out/err
    // in addition to children
    // on soft/gentle restarts headroom may be needed while children die
    // so use prefork_children as an estimate for this value.
    max_maxchildren = rlim.rlim_cur - (no_listen_fds + 6);
    int fd_needed = (o.http_workers *2) + no_listen_fds + 6;

    if (((o.http_workers * 2) ) > max_maxchildren) {
        e2logger_error("httpworkers option in e2guardian.conf has a value too high for current file id limit (", rlim.rlim_cur, ")" );
        e2logger_error("httpworkers ", o.http_workers,  " must not exceed 50% of ", max_maxchildren);
        e2logger_error("in this configuration.");
        e2logger_error("Reduce httpworkers ");
        e2logger_error("Or increase the filedescriptors available with ulimit -n to at least=", fd_needed);
        return 1; // we can't have rampant proccesses can we?
    }

    if (!o.proc.find_user_ids()) return 1;
    if (!o.proc.become_proxy_user()) return 1;

    // this is no longer a class, but the comment has been retained for historical reasons. PRA 03-10-2005
    //FatController f;  // Thomas The Tank Engine

    e2logger_trace("Starting Main loop");
    while (true) {
        int rc;

        rc = fc_controlit();
        // its a little messy, but I wanted to split
        // all the ground work and non-daemon stuff
        // away from the daemon class
        // However the line is not so fine.
        if (rc == 2) {

            // In order to re-read the conf files and create cache files
            // we need to become root user again
            if (!o.proc.become_root_user()) return 1;

            e2logger_trace("About to re-read conf file.");
            o.reset();
            if (!o.readConfig(o.config.configfile, true)) {
                // OptionContainer class had an error reading the conf or
                // other files so exit with error
                e2logger_error("Error re-parsing the e2guardian.conf file or other e2guardian configuration files");
                return 1;
            }
            e2logger_trace("conf file read.");

            while (waitpid(-1, NULL, WNOHANG) > 0) {
            } // mop up defunts

             // become low priv again
            if (!o.proc.become_proxy_user()) return 1;
            continue;
        }

        if (o.proc.is_daemonised)
        	return 0; // exit without error
        if (rc > 0) {
            e2logger_error("Exiting with error");
            return rc; // exit returning the error number
        }
    }
}


int readCommandlineOptions(int argc, char *argv[]){
    bool needreset = false;

    e2logger_trace("parse Options");
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (unsigned int j = 1; j < strlen(argv[i]); j++) {
                char option = argv[i][j];
                bool dobreak = false;
                switch (option) {
                case 'q':
                    if (!o.readConfig(o.config.configfile, true)) exit(-1);
                    return sysv_kill(o.pid_filename,true);
                case 'Q':
                    if (!o.readConfig(o.config.configfile, true)) exit(-1);
                    sysv_kill(o.pid_filename, false);
                    // give the old process time to die
                    while (sysv_amirunning(o.pid_filename))
                        sleep(1);
                    unlink(o.pid_filename.c_str());
                    // remember to reset config before continuing
                    needreset = true;
                    break;
                case 's':
                    if (!o.readConfig(o.config.configfile, true)) exit(-1);
                    return sysv_showpid(o.pid_filename);
                case 'r':
                    if (!o.readConfig(o.config.configfile, true)) exit(-1);
                    return sysv_hup(o.pid_filename);
                case 'g':
                    if (!o.readConfig(o.config.configfile, true)) exit(-1);
                    return sysv_usr1(o.pid_filename);
                case 'v':
                    std::cout << "e2guardian " << PACKAGE_VERSION << std::endl
                              << std::endl
                              << "Built with: " << E2_CONFIGURE_OPTIONS << std::endl;
                    return 0;
                case 'N':
                    o.proc.no_daemon = true;
                    break;
                case 'c':
                    if ((i + 1) < argc) {
                        o.config.configfile = argv[i + 1];
                        dobreak = true; // broken-ness of this option reported by Jason Gauthier 2006-03-09
                    } else {
                        std::cerr << "No config file specified!" << std::endl;
                        return 1;
                    }
                    break;
                case 'i':
                    o.lists.read_from_stdin = true;
                    break;
                case 'l':
                    if ((i + 1) < argc) {
                        loggerConfig.configure(argv[i+1]);
                    };
                    break;

                case 'h':
                    std::cout << "Usage: " << argv[0] << " [{-c ConfigFileName|-v|-P|-h|-N|-q|-s|-r|-g|-i}]" << std::endl;
                    std::cout << "  -v gives the version number and build options." << std::endl;
                    std::cout << "  -h gives this message." << std::endl;
                    std::cout << "  -c allows you to specify a different configuration file location." << std::endl;
                    std::cout << "  -N Do not go into the background." << std::endl;
                    std::cout << "  -q causes e2guardian to kill any running copy." << std::endl;
                    std::cout << "  -Q kill any running copy AND start a new one with current options." << std::endl;
                    std::cout << "  -s shows the parent process PID and exits." << std::endl;
                    std::cout << "  -r reloads lists and group config files by issuing a HUP," << std::endl;
                    std::cout << "     but this does not reset the httpworkers option (amongst others)." << std::endl;
                    std::cout << "  -g  same as -r  (Issues a USR1)" << std::endl;
                    std::cout << "  -i read lists from stdin" << std::endl;
#ifdef __BENCHMARK
                    std::cout << "  --bs benchmark searching filter group 1's bannedsitelist" << std::endl;
                    std::cout << "  --bu benchmark searching filter group 1's bannedurllist" << std::endl;
                    std::cout << "  --bp benchmark searching filter group 1's phrase lists" << std::endl;
                    std::cout << "  --bn benchmark filter group 1's NaughtyFilter in its entirety" << std::endl;
#endif
                    return 0;
#ifdef __BENCHMARK
                case '-':
                    if (strlen(argv[i]) != 4) {
                        std::cerr << "Invalid benchmark option" << std::endl;
                        return 1;
                    }
                    o.config.benchmark = argv[i][3];
                    dobreak = true;
                    break;
#endif
                }
                if (dobreak)
                    break; // skip to the next argument
            }
        }
    }


    if (needreset) {
        e2logger_trace("reset Options");
        o.reset();
    }

}

int runBenchmarks()
{
#ifdef __BENCHMARK
    TODO : Does not work in v5.5

    if (o.config.benchmark) {
        std::string results;
        char *found;
        struct tms then, now;
        std::string line;
        std::deque<String *> lines;

        while (!std::cin.eof()) {
            std::getline(std::cin, line);
            String *strline = new String(line);
            lines.push_back(strline);
        }
        String *strline = NULL;
        times(&then);
        switch (o.config.benchmark) {
        case 's':
            // bannedsitelist
            while (!lines.empty()) {
                strline = lines.back();
                lines.pop_back();
                if ((found = o.fg[0]->inBannedSiteList(*strline))) {
                    results += found;
                    results += '\n';
                }
                delete strline;
            }
            break;
        case 'u':
            // bannedurllist
            while (!lines.empty()) {
                strline = lines.back();
                lines.pop_back();
                if ((found = o.fg[0]->inBannedURLList(*strline))) {
                    results += found;
                    results += '\n';
                }
                delete strline;
            }
            break;
        case 'p': {
            // phraselists
            std::deque<unsigned int> found;
            std::string file;
            while (!lines.empty()) {
                strline = lines.back();
                lines.pop_back();
                file += strline->toCharArray();
                delete strline;
            }
            char cfile[file.length() + 129];
            memcpy(cfile, file.c_str(), sizeof(char) * file.length());
            o.lm.l[o.fg[0]->banned_phrase_list]->graphSearch(found, cfile, file.length());
            for (std::deque<unsigned int>::iterator i = found.begin(); i != found.end(); i++) {
                results += o.lm.l[o.fg[0]->banned_phrase_list]->getItemAtInt(*i);
                results += '\n';
            }
        } break;
        case 'n': {
            // NaughtyFilter
            std::string file;
            NaughtyFilter n;
            while (!lines.empty()) {
                strline = lines.back();
                lines.pop_back();
                file += strline->toCharArray();
                delete strline;
            }
            DataBuffer d(file.c_str(), file.length());
            String f;
            n.checkme(&d, f, f);
            std::cout << n.isItNaughty << std::endl
                      << n.whatIsNaughty << std::endl
                      << n.whatIsNaughtyLog << std::endl
                      << n.whatIsNaughtyCategories << std::endl;
        } break;
        default:
            std::cerr << "Invalid benchmark option" << std::endl;
            return 1;
        }
        times(&now);
        std::cout << results << std::endl
                  << "time: " << now.tms_utime - then.tms_utime << std::endl;
        return 0;
    }
#endif
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