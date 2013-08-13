//  File descriptor functions - generic functions for reading, writing,
//  and (in future) creating files
//  Please use *only* for files, not sockets!

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_FDFUNCS
#define __HPP_FDFUNCS


// INCLUDES

#include <unistd.h>
#include <cerrno>


// IMPLEMENTATION

// wrappers around FD read/write that restart on EINTR
int readEINTR(int fd, char *buf, unsigned int count);
int writeEINTR(int fd, char *buf, unsigned int count);

#endif
