// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "FatController.hpp"
#include "SysV.hpp"
#include "Queue.hpp"

#include <cstdlib>
#include <iostream>
#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <cerrno>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <fstream>
#include <fcntl.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/times.h>
#include <sys/resource.h>

#ifdef __BENCHMARK
#include <sys/times.h>
#include "NaughtyFilter.hpp"
#endif

// GLOBALS
#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

/*
#ifdef DANS_MAXFD
#undef FD_SETSIZE
#define FD_SETSIZE DANS_MAXFD
#endif
*/

#ifndef DANS_MAXFD
#define DANS_MAXFD FD_SETSIZE
#endif

OptionContainer o;

bool is_daemonised;

// regexp used during URL decoding by HTTPHeader
// we want it compiled once, not every time it's used, so do so on startup
RegExp urldecode_re;

#ifdef HAVE_PCRE
// regexes used for embedded URL extraction by NaughtyFilter
RegExp absurl_re, relurl_re;
#endif

// DECLARATIONS

// get the OptionContainer to read in the given configuration file
void read_config(std::string& configfile, int type);

// IMPLEMENTATION

// get the OptionContainer to read in the given configuration file
//void read_config(const char *configfile, int type)
void read_config(std::string& configfile, int type)
{
    int rc = open(configfile.c_str(), 0, O_RDONLY);
    if (rc < 0) {
        syslog(LOG_ERR, "Error opening %s", configfile.c_str());
        std::cerr << "Error opening " << configfile.c_str() << std::endl;
        exit(1); // could not open conf file for reading, exit with error
    }
    close(rc);

    if (!o.read(configfile, type)) {
        syslog(LOG_ERR, "%s", "Error parsing the e2guardian.conf file or other e2guardian configuration files");
        std::cerr << "Error parsing the e2guardian.conf file or other e2guardian configuration files" << std::endl;
        exit(1); // OptionContainer class had an error reading the conf or other files so exit with error
    }
}

// program entry point
int main(int argc, char *argv[])
{
    is_daemonised = false;
    bool nodaemon = false;
    bool needreset = false;
    bool total_block_list = false;
    std::string configfile(__CONFFILE);
    std::string prog_name("e2guardian");
    srand(time(NULL));
    int rc;

    openlog(prog_name.c_str(), LOG_PID | LOG_CONS, LOG_USER);

#ifdef DGDEBUG
    std::cout << "Running in debug mode..." << std::endl;
#endif

#ifdef __BENCHMARK
    char benchmark = '\0';
#endif

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (unsigned int j = 1; j < strlen(argv[i]); j++) {
                char option = argv[i][j];
                bool dobreak = false;
                switch (option) {
                case 'q':
                    read_config(configfile, 0);
                    return sysv_kill(o.pid_filename,true);
                case 'Q':
                    read_config(configfile, 0);
                    sysv_kill(o.pid_filename, false);
                    // give the old process time to die
                    while (sysv_amirunning(o.pid_filename))
                        sleep(1);
                    unlink(o.pid_filename.c_str());
                    // remember to reset config before continuing
                    needreset = true;
                    break;
                case 's':
                    read_config(configfile, 0);
                    return sysv_showpid(o.pid_filename);
                case 'r':
                    read_config(configfile, 0);
                    return sysv_hup(o.pid_filename);
                case 'g':
                    read_config(configfile, 0);
                    return sysv_usr1(o.pid_filename);
                case 'v':
                    std::cout << "e2guardian " << PACKAGE_VERSION << std::endl
                              << std::endl
                              << "Built with: " << DG_CONFIGURE_OPTIONS << std::endl;
                    return 0;
                case 'N':
                    nodaemon = true;
                    break;
                case 'c':
                    if ((i + 1) < argc) {
                        configfile = argv[i + 1];
                        dobreak = true; // broken-ness of this option reported by Jason Gauthier 2006-03-09
                    } else {
                        std::cerr << "No config file specified!" << std::endl;
                        return 1;
                    }
                    break;
                case 'i':
                    total_block_list = true;
                    o.use_total_block_list = total_block_list;
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
                    std::cout << "  -i read total block list from stdin" << std::endl;
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
                    benchmark = argv[i][3];
                    dobreak = true;
                    break;
#endif
                }
                if (dobreak)
                    break; // skip to the next argument
            }
        }
    }

    // Set current locale for proper character conversion
    setlocale(LC_ALL, "");

    if (needreset) {
        o.reset();
    }

    read_config(configfile, 2);

    if ( ! o.name_suffix.empty() ) {
      prog_name += o.name_suffix;
      closelog();
      openlog(prog_name.c_str(), LOG_PID | LOG_CONS, LOG_USER);
    }

    if (total_block_list && !o.readinStdin()) {
        syslog(LOG_ERR, "%s", "Error on reading total_block_list");
        std::cerr << "Error on reading total_block_list" << std::endl;
//		return 1;
#ifdef DGDEBUG
        std::cerr << "Total block lists read OK from stdin." << std::endl;

#endif
    }

#ifdef __BENCHMARK
    // run benchmarks instead of starting the daemon
    if (benchmark) {
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
        switch (benchmark) {
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
            std::cout << "What is naughty: "<< n.isItNaughty << std::endl
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

    if (sysv_amirunning(o.pid_filename)) {
        syslog(LOG_ERR, "%s", "I seem to be running already!");
        std::cerr << "I seem to be running already!" << std::endl;
        return 1; // can't have two copies running!!
    }

    if (nodaemon) {
        o.no_daemon = 1;
    }
    // calc the number of listening processes
    int no_listen_fds;
    if (o.map_ports_to_ips) {
        no_listen_fds = o.filter_ip.size();
    } else {
        no_listen_fds = o.filter_ports.size() * o.filter_ip.size();
    }

    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        syslog(LOG_ERR, "getrlimit call returned %d error", errno);
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
        syslog(LOG_ERR, "%s", "httpworkers option in e2guardian.conf has a value too high.");
        std::cerr << " httpworkers option in e2guardian.conf has a value too high for current file id limit (" << rlim.rlim_cur << ")" << std::endl;
        std::cerr << "httpworkers " << o.http_workers <<  " must not exceed 50% of " << max_maxchildren << "" << std::endl;
        std::cerr << "in this configuration." << std::endl;
        std::cerr << "Reduce httpworkers " << std::endl;
        std::cerr << "Or increase the filedescriptors available with ulimit -n to at least=" << fd_needed << std::endl;
        return 1; // we can't have rampant proccesses can we?
    }

    unsigned int rootuid; // prepare a struct for use later
    rootuid = geteuid();
    o.root_user = rootuid;

    struct passwd *st; // prepare a struct
    struct group *sg;

    // "daemongroup" option exists, but never used to be honoured. this is now
    // an important feature, however, because we need to be able to create temp
    // files with suitable permissions for scanning by AV daemons - we do this
    // by becoming a member of a specified AV group and setting group read perms
    if ((sg = getgrnam(o.daemon_group_name.c_str())) != 0) {
        o.proxy_group = sg->gr_gid;
    } else {
        syslog(LOG_ERR, "Unable to getgrnam(): %s", strerror(errno));
        syslog(LOG_ERR, "Check the group that e2guardian runs as (%s)", o.daemon_group_name.c_str());
        std::cerr << "Unable to getgrnam(): " << strerror(errno) << std::endl;
        std::cerr << "Check the group that e2guardian runs as (" << o.daemon_group_name.c_str() << ")" << std::endl;
        return 1;
    }

    if ((st = getpwnam(o.daemon_user_name.c_str())) != 0) { // find uid for proxy user
        o.proxy_user = st->pw_uid;

        rc = setgid(o.proxy_group); // change to rights of proxy user group
        // i.e. low - for security
        if (rc == -1) {
            syslog(LOG_ERR, "%s", "Unable to setgid()");
            std::cerr << "Unable to setgid()" << std::endl;
            return 1; // setgid failed for some reason so exit with error
        }
#ifdef HAVE_SETREUID
        rc = setreuid((uid_t)-1, st->pw_uid);
#else
        rc = seteuid(o.proxy_user); // need to be euid so can su back
// (yes it negates but no choice)
#endif
        if (rc == -1) {
            syslog(LOG_ERR, "Unable to seteuid()");
            std::cerr << "Unable to seteuid()" << std::endl;
            return 1; // seteuid failed for some reason so exit with error
        }
    } else {
        syslog(LOG_ERR, "Unable to getpwnam() - does the proxy user exist?");
        std::cerr << "Unable to getpwnam() - does the proxy user exist?" << std::endl;
        std::cerr << "Proxy user looking for is '" << o.daemon_user_name << "'" << std::endl;
        return 1; // was unable to lockup the user id from passwd
        // for some reason, so exit with error
    }

    if (!o.no_logger && !o.log_syslog) {
        std::ofstream logfiletest(o.log_location.c_str(), std::ios::app);
        if (logfiletest.fail()) {
            syslog(LOG_ERR, "Error opening/creating log file. (check ownership and access rights).");
            std::cout << "Error opening/creating log file. (check ownership and access rights)." << std::endl;
            std::cout << "I am running as " << o.daemon_user_name << " and I am trying to open " << o.log_location << std::endl;
            return 1; // opening the log file for writing failed
        }
        logfiletest.close();
    }

    urldecode_re.comp("%[0-9a-fA-F][0-9a-fA-F]"); // regexp for url decoding

#ifdef HAVE_PCRE
    // todo: these only work with PCRE enabled (non-greedy matching).
    // change them, or make them a feature for which you need PCRE?
    absurl_re.comp("[\"'](http|ftp)://.*?[\"']"); // find absolute URLs in quotes
    relurl_re.comp("(href|src)\\s*=\\s*[\"'].*?[\"']"); // find relative URLs in quotes
#endif

    // this is no longer a class, but the comment has been retained for historical reasons. PRA 03-10-2005
    //FatController f;  // Thomas The Tank Engine

    while (true) {
        rc = fc_controlit();
        // its a little messy, but I wanted to split
        // all the ground work and non-daemon stuff
        // away from the daemon class
        // However the line is not so fine.
        if (rc == 2) {

// In order to re-read the conf files and create cache files
// we need to become root user again

#ifdef HAVE_SETREUID
            rc = setreuid((uid_t)-1, rootuid);
#else
            rc = seteuid(rootuid);
#endif
            if (rc == -1) {
                syslog(LOG_ERR, "%s", "Unable to seteuid() to read conf files.");
#ifdef DGDEBUG
                std::cerr << "Unable to seteuid() to read conf files." << std::endl;
#endif
                return 1;
            }
#ifdef DGDEBUG
            std::cout << "About to re-read conf file." << std::endl;
#endif
            o.reset();
            if (!o.read(configfile, 2)) {
                syslog(LOG_ERR, "%s", "Error re-parsing the e2guardian.conf file or other e2guardian configuration files");
#ifdef DGDEBUG
                std::cerr << "Error re-parsing the e2guardian.conf file or other e2guardian configuration files" << std::endl;
#endif
                return 1;
                // OptionContainer class had an error reading the conf or
                // other files so exit with error
            }
#ifdef DGDEBUG
            std::cout << "conf file read." << std::endl;
#endif

            if (nodaemon) {
                o.no_daemon = 1;
            }

            while (waitpid(-1, NULL, WNOHANG) > 0) {
            } // mop up defunts

#ifdef HAVE_SETREUID
            rc = setreuid((uid_t)-1, st->pw_uid);
#else
            rc = seteuid(st->pw_uid); // become low priv again
#endif

            if (rc == -1) {
                syslog(LOG_ERR, "%s", "Unable to re-seteuid()");
#ifdef DGDEBUG
                std::cerr << "Unable to re-seteuid()" << std::endl;
#endif
                return 1; // seteuid failed for some reason so exit with error
            }
            continue;
        }

        if (rc > 0) {
            if (!is_daemonised) {
                std::cerr << "Exiting with error" << std::endl;
            }
            syslog(LOG_ERR, "%s", "Exiting with error");
            return rc; // exit returning the error number
        }
        return 0; // exit without error
    }
}
