// Default download manager, used when no other plugin matches the user agent

// For all support, instructions and copyright go to:
// http://dansguardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES
#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif

#include "../DownloadManager.hpp"
#include "../OptionContainer.hpp"

#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


// GLOBALS

extern OptionContainer o;


// DECLARATIONS

class dminstance:public DMPlugin
{
public:
	dminstance(ConfigVar & definition):DMPlugin(definition) {};
	int in(DataBuffer * d, Socket * sock, Socket * peersock, HTTPHeader * requestheader,
		HTTPHeader * docheader, bool wantall, int *headersent, bool * toobig);

	// default plugin is as basic as you can get - no initialisation, and uses the default
	// set of matching mechanisms. uncomment and implement these to override default behaviour.
	//int init(void* args);
	//bool willHandle(HTTPHeader *requestheader, HTTPHeader *docheader);
};


// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

DMPlugin *defaultdmcreate(ConfigVar & definition)
{
#ifdef DGDEBUG
	std::cout << "Creating default DM" << std::endl;
#endif
	return new dminstance(definition);
}

// end of Class factory

// uncomment these if you wish to replace the default inherited functions
// < 0 = error
// = 0 = ok
// > 0 = warning

//int dminstance::init(void* args) {
//	return 0;
//}
//int dminstance::quit(void) {
//	return 0;
//}

// download body for this request
int dminstance::in(DataBuffer * d, Socket * sock, Socket * peersock, class HTTPHeader * requestheader,
	class HTTPHeader * docheader, bool wantall, int *headersent, bool * toobig)
{

	//DataBuffer *d = where to stick the data back into
	//Socket *sock = where to read from
	//Socket *peersock = browser to send stuff to for keeping it alive
	//HTTPHeader *requestheader = header client used to request
	//HTTPHeader *docheader = header used for sending first line of reply
	//bool wantall = to determine if just content filter or a full scan
	//int *headersent = to use to send the first line of header if needed
	//                                or to mark the header has already been sent
	//bool *toobig = flag to modify to say if it could not all be downloaded

#ifdef DGDEBUG
	std::cout << "Inside default download manager plugin" << std::endl;
#endif

//  To access settings for the plugin use the following example:
//      std::cout << "cvtest:" << cv["dummy"] << std::endl;

	int rc;
	off_t newsize;
	off_t bytesremaining = docheader->contentLength();
	
	// if using non-persistent connections, some servers will not report
	// a content-length. in these situations, just download everything.
	bool geteverything = false;
	if ((bytesremaining < 0) && !(docheader->isPersistent()))
		geteverything = true;

	char *block = NULL;  // buffer for storing a grabbed block from the
	// imput stream
	char *temp = NULL;

	bool swappedtodisk = false;
	bool doneinitialdelay = false;

	struct timeval themdays;
	struct timeval nowadays;
	gettimeofday(&themdays, NULL);

	// buffer size for streaming downloads
	off_t blocksize = 32768;
	// set to a sensible minimum
	if (!wantall && (blocksize > o.max_content_filter_size))
		blocksize = o.max_content_filter_size;
	else if (wantall && (blocksize > o.max_content_ramcache_scan_size))
		blocksize = o.max_content_ramcache_scan_size;
#ifdef DGDEBUG
	std::cout << "blocksize: " << blocksize << std::endl;
#endif

	while ((bytesremaining > 0) || geteverything) {
		// send x-header keep-alive here
		if (o.trickle_delay > 0) {
			gettimeofday(&nowadays, NULL);
			if (doneinitialdelay ? nowadays.tv_sec - themdays.tv_sec > o.trickle_delay : nowadays.tv_sec - themdays.tv_sec > o.initial_trickle_delay) {
				themdays.tv_sec = nowadays.tv_sec;
				doneinitialdelay = true;
				if ((*headersent) < 1) {
#ifdef DGDEBUG
					std::cout << "sending first line of header first" << std::endl;
#endif
					docheader->out(NULL,peersock, __DGHEADER_SENDFIRSTLINE);
					(*headersent) = 1;
				}
#ifdef DGDEBUG
				std::cout << "trickle delay - sending X-DGKeepAlive: on" << std::endl;
#endif
				peersock->writeString("X-DGKeepAlive: on\r\n");
			}
		}

		if (wantall) {
			if (!swappedtodisk) {
				// if not swapped to disk and file is too large for RAM, then swap to disk
				if (d->buffer_length > o.max_content_ramcache_scan_size) {
#ifdef DGDEBUG
					std::cout << "swapping to disk" << std::endl;
#endif
					d->tempfilefd = d->getTempFileFD();
					if (d->tempfilefd < 0) {
#ifdef DGDEBUG
						std::cerr << "error buffering to disk so skipping disk buffering" << std::endl;
#endif
						syslog(LOG_ERR, "%s", "error buffering to disk so skipping disk buffering");
						(*toobig) = true;
						break;
					}
					writeEINTR(d->tempfilefd, d->data, d->buffer_length);
					swappedtodisk = true;
					d->tempfilesize = d->buffer_length;
				}
			} else if (d->tempfilesize > o.max_content_filecache_scan_size) {
				// if swapped to disk and file too large for that too, then give up
#ifdef DGDEBUG
				std::cout << "defaultdm: file too big to be scanned, halting download" << std::endl;
#endif
				(*toobig) = true;
				break;
			}
		} else {
			if (d->buffer_length > o.max_content_filter_size) {
				// if we aren't downloading for virus scanning, and file too large for filtering, give up
#ifdef DGDEBUG
				std::cout << "defaultdm: file too big to be filtered, halting download" << std::endl;
#endif
				(*toobig) = true;
				break;
			}
		}

		if (!swappedtodisk) {
			if (d->buffer_length >= blocksize) {
				newsize = d->buffer_length;
			} else {
				newsize = blocksize;
			}
#ifdef DGDEBUG
			std::cout << "newsize: " << newsize << std::endl;
#endif
			// if not getting everything until connection close, grab only what is left
			if (!geteverything && (newsize > bytesremaining))
				newsize = bytesremaining;
			delete[] block;
			block = new char[newsize];
			try {
				sock->checkForInput(d->timeout);
			} catch(std::exception & e) {
				break;
			}
			// improved more efficient socket read which uses the buffer better
			rc = d->bufferReadFromSocket(sock, block, newsize, d->timeout);
			// grab a block of input, doubled each time

			if (rc <= 0) {
				break;  // an error occured so end the while()
				// or none received so pipe is closed
			}
			else {
				bytesremaining -= rc;
				/*if (d->data != temp)
					delete[] temp;*/
				temp = new char[d->buffer_length + rc + 1];  // replacement store
				temp[d->buffer_length + rc] = '\0';
				memcpy(temp, d->data, d->buffer_length);  // copy the current data
				memcpy(temp + d->buffer_length, block, rc);  // copy the new data
				delete[]d->data;  // delete the current data block
				d->data = temp;
				temp = NULL;
				d->buffer_length += rc;  // update data size counter
			}
		} else {
			try {
				sock->checkForInput(d->timeout);
			}
			catch(std::exception & e) {
				break;
			}
			rc = d->bufferReadFromSocket(sock, d->data,
				// if not getting everything until connection close, grab only what is left
				(!geteverything && (bytesremaining < d->buffer_length) ? bytesremaining : d->buffer_length), d->timeout);
			if (rc <= 0) {
				break;
			}
			else {
				bytesremaining -= rc;
				lseek(d->tempfilefd, 0, SEEK_END);  // not really needed
				writeEINTR(d->tempfilefd, d->data, rc);
				d->tempfilesize += rc;
#ifdef DGDEBUG
				std::cout << "written to disk:" << rc << " total:" << d->tempfilesize << std::endl;
#endif
			}
		}
	}

	if (!(*toobig) && !swappedtodisk) {	// won't deflate stuff swapped to disk
		if (d->decompress.contains("deflate")) {
#ifdef DGDEBUG
			std::cout << "zlib format" << std::endl;
#endif
			d->zlibinflate(false);  // incoming stream was zlib compressed
		}
		else if (d->decompress.contains("gzip")) {
#ifdef DGDEBUG
			std::cout << "gzip format" << std::endl;
#endif
			d->zlibinflate(true);  // incoming stream was gzip compressed
		}
	}
	d->bytesalreadysent = 0;
#ifdef DGDEBUG
	std::cout << "Leaving default download manager plugin" << std::endl;
#endif
	delete[] block;
	/*if (d->data != temp)
		delete[] temp;*/
	return 0;
}
