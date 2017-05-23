//  File descriptor functions - generic functions for reading, writing,
//  and (in future) creating files
//  Please use *only* for files, not sockets!

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "dgconfig.h"
#endif
#include "FDFuncs.hpp"

// IMPLEMENTATION

// wrapper around FD read that restarts on EINTR
int readEINTR(int fd, char *buf, unsigned int count)
{
    return read(fd, buf, count);
  //  int rc;
  //  errno = 0;
  //  while (true) { // using the while as a restart point with continue
   //     rc = read(fd, buf, count);
 //       if (rc < 0) {
 //           if (errno == EINTR) {
 ///               continue; // was interupted by a signal so restart
 //           }
 //       }
 //       break; // end the while
  //  }
  //  return rc; // return status
}

// wrapper around FD write that restarts on EINTR
int writeEINTR(int fd, char *buf, unsigned int count)
{
return write(fd, buf, count);
//    int rc;
//    errno = 0;
//    while (true) { // using the while as a restart point with continue
//        rc = write(fd, buf, count);
//        if (rc < 0) {
//            if (errno == EINTR) {
//                continue; // was interupted by a signal so restart
 //           }
//        }
//        break; // end the while
//    }
//    return rc; // return status
}
