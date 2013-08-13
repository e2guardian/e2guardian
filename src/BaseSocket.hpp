// BaseSocket class - inherit & implement to make UNIX/INET domain sockets

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_BASESOCKET
#define __HPP_BASESOCKET


// INCLUDES

#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <exception>
#include <netinet/in.h>
#include <arpa/inet.h>

int selectEINTR(int numfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, struct timeval *timeout, bool honour_reloadconfig = false);

class BaseSocket
{
public:
	// create socket from FD - must be overridden to clear the relevant address structs in derived classes
	BaseSocket(int fd);

	// make a socket a listening server socket
	int listen(int queue);

	// grab socket's FD, e.g. for passing to selectEINTR
	// use sparingly, and DO NOT do manual data transfer with it
	int getFD();
	
	// close socket
	void close();
	
	// set socket-wide timeout (is this actually used? all methods accept their own individual timeouts)
	void setTimeout(int t);
	// get timeout (is this actually used?)
	int getTimeout();

	// close & reset the connection - these must clear address structures & call baseReset/baseAccept
	virtual void reset()=0;
	virtual BaseSocket* accept()=0;

	// non-blocking check for input data
	bool checkForInput();
	// blocking check for data, can be told to break on signal triggered config reloads (-r)
	void checkForInput(int timeout, bool honour_reloadconfig = false) throw(std::exception);
	// non-blocking check for writable socket
	bool readyForOutput();
	// blocking check, can break on config reloads
	void readyForOutput(int timeout, bool honour_reloadconfig = false) throw(std::exception);
	
	// get a line from the socket - can break on config reloads
	int getLine(char *buff, int size, int timeout, bool honour_reloadconfig = false, bool *chopped = NULL, bool *truncated = NULL) throw(std::exception);
	
	// write buffer to string - throws std::exception on error
	void writeString(const char *line) throw(std::exception);
	// write buffer to string - can be told not to do an initial readyForOutput, and told to break on -r
	bool writeToSocket(const char *buff, int len, unsigned int flags, int timeout, bool check_first = true, bool honour_reloadconfig = false);
	// read from socket, returning number of bytes read
	int readFromSocketn(char *buff, int len, unsigned int flags, int timeout);
	// read from socket, returning error status - can be told to skip initial checkForInput, and to break on -r
	int readFromSocket(char *buff, int len, unsigned int flags, int timeout, bool check_first = true, bool honour_reloadconfig = false);
	// write to socket, throwing std::exception on error - can be told to break on -r
	void writeToSockete(const char *buff, int len, unsigned int flags, int timeout, bool honour_reloadconfig = false) throw(std::exception);

protected:
	// socket-wide timeout (is this actually used?)
	int timeout;
	// length of address of other end of socket (e.g. size of sockaddr_in or sockaddr_un)
	socklen_t peer_adr_length;
	// socket FD
	int sck;
	// internal buffer
	char buffer[1024];
	int buffstart;
	int bufflen;

	// constructor - sets default values. override this if you actually wish to create a default socket.
	BaseSocket();
	// destructor - closes socket
	virtual ~BaseSocket();
	
	// performs accept(). call from derived classes' accept method
	int baseAccept(struct sockaddr *acc_adr, socklen_t *acc_adr_length);
	// closes socket & resets timeout to default - call from derived classes' reset method
	void baseReset();
};

#endif
