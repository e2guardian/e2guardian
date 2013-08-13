// UDSocket class - implements BaseSocket for UNIX domain sockets

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_UDSOCKET
#define __HPP_UDSOCKET


// INCLUDES

#include "BaseSocket.hpp"


// DECLARATIONS

class UDSocket : public BaseSocket
{
public:
	// create default UNIX domain socket & clear address structs
	UDSocket();
	// create socket from pre-existing FD (address structs will be empty!)
	UDSocket(int fd);
	// create socket from FD & local path (checkme: is it actually local that gets passed?)
	UDSocket(int newfd, struct sockaddr_un myadr);
	
	// connect socket to given server (following default constructor)
	int connect(const char *path);
	// bind socket to given path (for creating servers)
	int bind(const char *path);
	
	// accept incoming connection & return new UDSocket
	UDSocket* accept();
	
	// close connection & clear address structs
	void reset();

private:
	// local & remote address structs
	struct sockaddr_un my_adr;
	struct sockaddr_un peer_adr;
	socklen_t my_adr_length;
};

#endif
