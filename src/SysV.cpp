// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "SysV.hpp"

#include <cstdio>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>
#include <csignal>
#include <climits>
#include <sys/types.h>
#include <sys/stat.h>
#include <cerrno>


// GLOBALS

extern OptionContainer o;


// DECLARATIONS

// get the PID from the given file, or by looking for "dansguardian" process by name - returns -1 if process not running
pid_t getpid(std::string pidfile);
// read process number from file (straight file read, no is-it-running check)
pid_t getpidfromfile(std::string pidfile);
// get PID from processes matching this command name (UNIMPLEMENTED)
pid_t getpidfromcommand(const char *command);
// confirm pid corresponds to a currently running process
bool confirmname(pid_t p);


// IMPLEMENTATION

// grab the PID from the file & check it's running (returns -1 on failure)
// (also checks process names if file method fails, but this is unimplemented)
pid_t getpid(std::string pidfile)
{
	pid_t p = getpidfromfile(pidfile);
	if (p > 1) {
		if (confirmname(p)) {	// is that pid really DG and running?
			return p;  // it is so return it
		}
	}
	pid_t t = getpidfromcommand("dansguardian");  // pid file method failed
	// so try a search from the
	// command
	return t;  // if it failed t will be -1
}

// grab process number from file (no run check)
pid_t getpidfromfile(std::string pidfile)
{
	int handle = open(pidfile.c_str(), O_RDONLY);
	if (handle < 0) {	// Unable to open the pid file.
		return -1;
	}
	char pidbuff[32];
	int rc = read(handle, pidbuff, sizeof(pidbuff) - 1);
	if (rc < 1) {		// pid file must be at least 1 byte long
		close(handle);
		return -1;
	}
	pidbuff[rc] = '\0';
	close(handle);
	return atoi(pidbuff);  // convert the string to a pid
}

// grab process number from processes matching the given command
pid_t getpidfromcommand(const char *command)
{
	return -1;  // ******** NOT IMPLEMENTED YET ************
	// only needed if the pid file gets deleted.

	//I KNOW HOW TO DO THIS IN A PORTABLE LINUX/BSD WAY
	//BUT I HAVE NOT HAD THE TIME TO ADD IT YET AS THIS
	//IS FUNCTIONAL ENOUGH TO WORK
}

// check the given PID is alive and running
bool confirmname(pid_t p)
{
	int rc =::kill(p, 0);  // just a test
	if (rc != 0) {
		if (errno == EPERM) {
			return true;  // we got no perms to test it but it must be there
		}
		return false;  // no process running at that pid
	}
	// ******** NOT FULLY IMPLEMENTED YET ************

	//I KNOW HOW TO DO THIS IN A PORTABLE LINUX/BSD WAY
	//BUT I HAVE NOT HAD THE TIME TO ADD IT YET AS THIS
	//IS FUNCTIONAL ENOUGH TO WORK

	return true;
}

// kill process in the pidfile, optionally deleting the pidfile & URL cache/logger IPC sockets
int sysv_kill(std::string pidfile, bool dounlink)
{
	pid_t p = getpid(pidfile);
	if (p > 1) {
		int rc =::kill(p, SIGTERM);
		if (rc == -1) {
			std::cerr << "Error trying to kill pid:" << p << std::endl;
			if (errno == EPERM) {
				std::cerr << "Permission denied." << std::endl;
			}
			return 1;
		}
		if (dounlink) {
			unlink(pidfile.c_str());
			unlink(o.ipc_filename.c_str());
			unlink(o.urlipc_filename.c_str());
		}
		return 0;
	}
	std::cerr << "No DansGuardian process found." << std::endl;
	return 1;
}

// send HUP to process
int sysv_hup(std::string pidfile)
{
	pid_t p = getpid(pidfile);
	if (p > 1) {
		int rc =::kill(p, SIGHUP);
		if (rc == -1) {
			std::cerr << "Error trying to hup pid:" << p << std::endl;
			if (errno == EPERM) {
				std::cerr << "Permission denied." << std::endl;
			}
			return 1;
		}
		return 0;
	}
	std::cerr << "No DansGuardian process found." << std::endl;
	return 1;
}

// send USR1 to process
int sysv_usr1(std::string pidfile)
{
	pid_t p = getpid(pidfile);
	if (p > 1) {
		int rc =::kill(p, SIGUSR1);
		if (rc == -1) {
			std::cerr << "Error trying to sig1 pid:" << p << std::endl;
			if (errno == EPERM) {
				std::cerr << "Permission denied." << std::endl;
			}
			return 1;
		}
		return 0;
	}
	std::cerr << "No DansGuardian process found." << std::endl;
	return 1;
}

// show PID of running DG process
int sysv_showpid(std::string pidfile)
{
	pid_t p = getpid(pidfile);
	if (p > 1) {
		std::cout << "Parent DansGuardian pid:" << p << std::endl;
		return 0;
	}
	std::cerr << "No DansGuardian process found." << std::endl;
	return 1;
}

// create a new pidfile
int sysv_openpidfile(std::string pidfile)
{
	unlink(pidfile.c_str());
	return open(pidfile.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
}

// write pid to file & close it
int sysv_writepidfile(int pidfilefd)
{
	pid_t p = getpid();
	char pidbuff[32];
	sprintf(pidbuff, "%d", (int) p);  // Messy, but it works!
	int len = strlen(pidbuff) + 1;
	pidbuff[len - 1] = '\n';
	int rc = write(pidfilefd, pidbuff, len);
	if (rc < len) {		// failed to write
		close(pidfilefd);
		return 1;
	}
	close(pidfilefd);
	return 0;
}

// check process in pidfile is running
bool sysv_amirunning(std::string pidfile)
{
	if (getpid(pidfile) > 1) {
		return true;
	}
	return false;
}
