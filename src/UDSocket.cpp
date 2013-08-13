// UDSocket class - implements BaseSocket for UNIX domain sockets

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "UDSocket.hpp"

#include <syslog.h>
#include <csignal>
#include <fcntl.h>
#include <sys/time.h>
#include <pwd.h>
#include <cerrno>
#include <unistd.h>
#include <stdexcept>
#include <stddef.h>

#ifdef DGDEBUG
#include <iostream>
#endif

// necessary for calculating size of sockaddr_un in a portable manner

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((size_t) &((TYPE *) 0)->MEMBER)
#endif

// IMPLEMENTATION

// constructor - creates default UNIX domain socket & clears address structs
UDSocket::UDSocket()
{
	sck = socket(PF_UNIX, SOCK_STREAM, 0);
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sun_family = AF_UNIX;
	strcpy(my_adr.sun_path, "");
	peer_adr.sun_family = AF_UNIX;
	strcpy(peer_adr.sun_path, "");
	my_adr_length = 0;
}

// create socket from pre-existing FD (address structs will be invalid!)
UDSocket::UDSocket(int fd):BaseSocket(fd)
{
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sun_family = AF_UNIX;
        strcpy(my_adr.sun_path, "");
        peer_adr.sun_family = AF_UNIX;
        strcpy(peer_adr.sun_path, "");
	my_adr_length = 0;
}

// create socket from given FD & local address (checkme: is it local or remote that gets passed in here?)
UDSocket::UDSocket(int newfd, struct sockaddr_un myadr):BaseSocket(newfd)
{
	my_adr = myadr;
	my_adr_length = sizeof(my_adr.sun_family) + strlen(my_adr.sun_path);
}

// close socket & clear address structs
void UDSocket::reset()
{
	this->baseReset();
	sck = socket(PF_UNIX, SOCK_STREAM, 0);
	memset(&my_adr, 0, sizeof my_adr);
	memset(&peer_adr, 0, sizeof peer_adr);
	my_adr.sun_family = AF_UNIX;
        strcpy(my_adr.sun_path, "");
        peer_adr.sun_family = AF_UNIX;
        strcpy(peer_adr.sun_path, "");
	my_adr_length = 0;
}

// accept incoming connection & return new UDSocket
UDSocket* UDSocket::accept()
{
	my_adr_length = sizeof(my_adr.sun_family) + strlen(my_adr.sun_path);
	int newfd = this->baseAccept((struct sockaddr*) &my_adr, &my_adr_length);
	UDSocket* s = new UDSocket(newfd, my_adr);
	return s;
}

// connect to given server (following default constructor)
int UDSocket::connect(const char *path)
{
	if(strlen(path) > 108)
		return -1;

#ifdef DGDEBUG
	std::cout << "uds connect:" << path << std::endl;
#endif
	strcpy(my_adr.sun_path, path);

	my_adr_length = offsetof(struct sockaddr_un, sun_path) + strlen(path);

	return ::connect(sck, (struct sockaddr *) &my_adr, my_adr_length);
}

// bind socket to given path
int UDSocket::bind(const char *path)
{				// to bind a unix domain socket to a path
	if(strlen(path) > 108)
		return -1;

	unlink(path);

	strcpy(my_adr.sun_path, path);

	my_adr_length = offsetof(struct sockaddr_un, sun_path) + strlen(path);

	return ::bind(sck, (struct sockaddr *) &my_adr, my_adr_length);
}
