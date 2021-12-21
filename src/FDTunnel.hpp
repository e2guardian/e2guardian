// This class is a generic multiplexing tunnel
// that uses blocking select() to be as efficient as possible.  It tunnels
// between the two supplied FDs.

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_FDTUNNEL
#define __HPP_FDTUNNEL

// INCLUDES

#include "Socket.hpp"
#include <fcntl.h>
#include <cstdbool>

// DECLARATIONS

// transparently forward data from one FD to another, i.e. tunnel between them
class FDTunnel
{
    public:
    off_t throughput; // used to log total data from from to to

    FDTunnel();

    // tunnel from fdfrom to fdto
    // return false if throughput larger than target throughput (for post upload size checking)
    bool tunnel(Socket &sockfrom, Socket &sockto, bool twoway = false, off_t targetthroughput = -1, bool ignore = false,
        bool chunked = false);

    void reset();

private:
    struct pollfd fromoutfds[1];
    struct pollfd tooutfds[1];
    struct pollfd twayfds[2];
    int timeout = 120000;
    char sfbuff[32768]; // buffer for the input

    bool nots2nots_tunnel(Socket &sockfrom, Socket &sockto, int &fdto, int &fdfrom, bool twoway, off_t targetthroughput,
                              bool ignore);
    bool iss2nots_tunnel(Socket &sockfrom, Socket &sockto, int &fdto, int &fdfrom, bool twoway, off_t targetthroughput,
                          bool ignore);
    bool iss2iss_tunnel(Socket &sockfrom, Socket &sockto, int &fdto, int &fdfrom, bool twoway, off_t targetthroughput,
                         bool ignore);
};

#endif
