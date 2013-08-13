// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_SYSV
#define __HPP_SYSV


// INCLUDES

#include "OptionContainer.hpp"

#include <sys/types.h>
#include <string>


// DECLARATIONS

// Kill the process specified in the given pidfile, optionally deleting the pidfile while we're at it,
// along with the UNIX domain sockets for the old logger & url cache
int sysv_kill(std::string pidfile, bool dounlink = true);

// show PID of running DG process
int sysv_showpid(std::string pidfile);
// check that the process in the pidfile is running
bool sysv_amirunning(std::string pidfile);

// delete any existing file with this name, and create a new one with relevant mode flags
int sysv_openpidfile(std::string pidfile);
// write our pid to the given file & close it
int sysv_writepidfile(int pidfilefd);

// send HUP or USR1 to the process in the pidfile
int sysv_hup(std::string pidfile);
int sysv_usr1(std::string pidfile);

#endif
