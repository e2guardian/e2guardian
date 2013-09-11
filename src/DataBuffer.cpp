// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.


// INCLUDES

#ifdef HAVE_CONFIG_H
	#include "dgconfig.h"
#endif
#include "HTTPHeader.hpp"
#include "OptionContainer.hpp"

#include <sys/stat.h>
#include <syslog.h>
#include <algorithm>
#include <cstdlib>
#include <unistd.h>
#include <zlib.h>
#include <cerrno>
#include <fstream>
#include <sys/time.h>
#include <queue>
#include <istream>

// DEFINES

#define __DGHEADER_SENDALL 0
#define __DGHEADER_SENDFIRSTLINE 1
#define __DGHEADER_SENDREST 2

// GLOBALS

extern OptionContainer o;


// IMPLEMENTATION

DataBuffer::DataBuffer():data(new char[1]), buffer_length(0), compresseddata(NULL), compressed_buffer_length(0),
	tempfilesize(0), dontsendbody(false), tempfilefd(-1), dm_plugin(NULL), timeout(20), bytesalreadysent(0), preservetemp(false)
{
	data[0] = '\0';
}

DataBuffer::DataBuffer(const void* indata, off_t length):data(new char[length]), buffer_length(length), compresseddata(NULL), compressed_buffer_length(0),
	tempfilesize(0), dontsendbody(false), tempfilefd(-1), timeout(20), bytesalreadysent(0), preservetemp(false)
{
	memcpy(data, indata, length);
}

void DataBuffer::reset()
{
	delete[]data;
	delete[]compresseddata;

	data = new char[1];
	data[0] = '\0';

	compresseddata = NULL;

	buffer_length = 0;
	compressed_buffer_length = 0;

	if (tempfilefd > -1) {
		close(tempfilefd);
		if (!preservetemp) {
			unlink(tempfilepath.toCharArray());
		}
		tempfilefd = -1;
		tempfilesize = 0;
	}

	bytesalreadysent = 0;
	dontsendbody = false;
	preservetemp = false;
	decompress = "";
}

// delete the memory block when the class is destroyed
DataBuffer::~DataBuffer()
{
	delete[]data;
	if (compresseddata != NULL) {
		delete[]compresseddata;
		compresseddata = NULL;
	}
	if (tempfilefd > -1) {
		close(tempfilefd);
		if (!preservetemp) {
			unlink(tempfilepath.toCharArray());
		}
		tempfilefd = -1;
		tempfilesize = 0;
	}
}

// swap back to a compressed version of the data, if one exits
// also delete uncompressed version
// if body was decompressed but not modified, this can save bandwidth
void DataBuffer::swapbacktocompressed()
{
	if (compresseddata != NULL && compressed_buffer_length > 0) {
		delete[]data;
		buffer_length = compressed_buffer_length;
		data = compresseddata;
		compresseddata = NULL;
		compressed_buffer_length = 0;
	}	
}

// a much more efficient reader that does not assume the contents of
// the buffer gets filled thus reducing memcpy()ing and new()ing
int DataBuffer::bufferReadFromSocket(Socket * sock, char *buffer, int size, int sockettimeout)
{
	int pos = 0;
	int rc;
	while (pos < size) {
		rc = sock->readFromSocket(&buffer[pos], size - pos, 0, sockettimeout);
		if (rc < 1) {
			// none recieved or an error
			if (pos > 0) {
				return pos;  // some was recieved previous into buffer
			}
			return rc;  // just return with the return code
		}
		pos += rc;
	}
	return size;  // full buffer
}

// a much more efficient reader that does not assume the contents of
// the buffer gets filled thus reducing memcpy()ing and new()ing.
// in addition to the actual socket timeout, used for each individual read, this version
// incorporates a "global" timeout within which all reads must complete.
int DataBuffer::bufferReadFromSocket(Socket * sock, char *buffer, int size, int sockettimeout, int timeout)
{

	int pos = 0;
	int rc;
	struct timeval starttime;
	struct timeval nowadays;
	gettimeofday(&starttime, NULL);
	while (pos < size) {
		rc = sock->readFromSocket(&buffer[pos], size - pos, 0, sockettimeout, false);
		if (rc < 1) {
			// none recieved or an error
			if (pos > 0) {
				return pos;  // some was recieved previous into buffer
			}
			return rc;  // just return with the return code
		}
		pos += rc;
		gettimeofday(&nowadays, NULL);
		if (nowadays.tv_sec - starttime.tv_sec > timeout) {
#ifdef DGDEBUG
			std::cout << "buffered socket read more than timeout" << std::endl;
#endif
			return pos;  // just return how much got so far then
		}
	}
	return size;  // full buffer
}

// make a temp file and return its FD. only currently used in DM plugins.
int DataBuffer::getTempFileFD()
{
	if (tempfilefd > -1) {
		return tempfilefd;
	}
	tempfilepath = o.download_dir.c_str();
	tempfilepath += "/tfXXXXXX";
	char *tempfilepatharray = new char[tempfilepath.length() + 1];
	strcpy(tempfilepatharray, tempfilepath.toCharArray());
	umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if ((tempfilefd = mkstemp(tempfilepatharray)) < 0) {
#ifdef DGDEBUG
		std::cerr << "error creating temp " << tempfilepath << ": " << strerror(errno) << std::endl;
#endif
		syslog(LOG_ERR, "Could not create temp file to store download for scanning: %s", strerror(errno));
		tempfilefd = -1;
		tempfilepath = "";
	} else {
		tempfilepath = tempfilepatharray;
	}
	delete[]tempfilepatharray;
	return tempfilefd;
}

// check the client's user agent, see if we have a DM plugin compatible with it, and use it to download the body of the given request
bool DataBuffer::in(Socket * sock, Socket * peersock, HTTPHeader * requestheader, HTTPHeader * docheader, bool runav, int *headersent)
{
	//Socket *sock = where to read from
	//Socket *peersock = browser to send stuff to for keeping it alive
	//HTTPHeader *requestheader = header client used to request
	//HTTPHeader *docheader = header used for sending first line of reply
	//bool runav = to determine if limit is av or not
	//int *headersent = to use to send the first line of header if needed
	//				  or to mark that the header has already been sent

	// so we know if we only partially downloaded from
	// squid so later, if allowed, we can send the rest
	bool toobig = false;

	// match request to download manager so browsers potentially can have a prettier version
	// and software updates, stream clients, etc. can have a compatible version.
	int rc = 0;
# ifdef DGDEBUG
	int j = 0;
#endif
	for (std::deque<Plugin *>::iterator i = o.dmplugins_begin; i != o.dmplugins_end; i++) {
		if ((i + 1) == o.dmplugins_end) {
#ifdef DGDEBUG
			std::cerr << "Got to final download manager so defaulting to always match." << std::endl;
#endif
			dm_plugin = (DMPlugin*)(*i);
			rc = dm_plugin->in(this, sock, peersock, requestheader, docheader, runav, headersent, &toobig);
			break;
		} else {
			if (((DMPlugin*)(*i))->willHandle(requestheader, docheader)) {
#ifdef DGDEBUG
				std::cerr << "Matching download manager number: " << j << std::endl;
#endif
				dm_plugin = (DMPlugin*)(*i);
				rc = dm_plugin->in(this, sock, peersock, requestheader, docheader, runav, headersent, &toobig);
				break;
			}
		}
#ifdef DGDEBUG
		j++;
#endif
	}
	// we should check rc and log on error/warn
	// note for later - Tue 16th November 2004
	return toobig;
}

// send the request body to the client after having been handled by a DM plugin
void DataBuffer::out(Socket * sock) throw(std::exception)
{
	if (dontsendbody) {
#ifdef DGDEBUG
		std::cout << "dontsendbody true; not sending" << std::endl;
#endif
		return;
	}
	(*sock).readyForOutput(timeout);  // exceptions on timeout or error

	if (tempfilefd > -1) {
		// must have been too big for ram so stream from disk in blocks
#ifdef DGDEBUG
		std::cout << "Sending " << tempfilesize - bytesalreadysent << " bytes from temp file (" << bytesalreadysent << " already sent)" << std::endl;
#endif
		off_t sent = bytesalreadysent;
		int rc;

		if (lseek(tempfilefd, bytesalreadysent, SEEK_SET) < 0)
			throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));

		while (sent < tempfilesize) {
			rc = readEINTR(tempfilefd, data, buffer_length);
#ifdef DGDEBUG
			std::cout << "reading temp file rc:" << rc << std::endl;
#endif
			if (rc < 0) {
#ifdef DGDEBUG
				std::cout << "error reading temp file so throwing exception" << std::endl;
#endif
				throw std::exception();
			}
			if (rc == 0) {
#ifdef DGDEBUG
				std::cout << "got zero bytes reading temp file" << std::endl;
#endif
				break;  // should never happen
			}
			// as it's cached to disk the buffer must be reasonably big
			if (!sock->writeToSocket(data, rc, 0, timeout)) {
				throw std::runtime_error(std::string("Can't write to socket: ") + strerror(errno));
			}
			sent += rc;
#ifdef DGDEBUG
			std::cout << "total sent from temp:" << sent << std::endl;
#endif
		}
		close(tempfilefd);
		tempfilefd = -1;
		tempfilesize = 0;
		unlink(tempfilepath.toCharArray());
	} else {
#ifdef DGDEBUG
		std::cout << "Sending " << buffer_length - bytesalreadysent << " bytes from RAM (" << buffer_length << " in buffer; " << bytesalreadysent << " already sent)" << std::endl;
#endif
		// it's in RAM, so just send it, no streaming from disk
		if (buffer_length != 0) {
			if (!sock->writeToSocket(data + bytesalreadysent, buffer_length - bytesalreadysent, 0, timeout))
				throw std::exception();
		} else {
			if (!sock->writeToSocket("\r\n\r\n", 4, 0, timeout))
				throw std::exception();
		}
	}
}

// zlib decompression
void DataBuffer::zlibinflate(bool header)
{
	if (buffer_length < 12) {
		return;  // it can't possibly be zlib'd
	}
#ifdef DGDEBUG
	std::cout << "compressed size:" << buffer_length << std::endl;
#endif

#if ZLIB_VERNUM < 0x1210
#warning ************************************
#warning For gzip support you need zlib 1.2.1
#warning or later to be installed.
#warning You can ignore this warning but
#warning internet bandwidth may be wasted.
#warning ************************************
	if (header) {
		return;
	}
#endif

	int newsize = buffer_length * 5;  // good estimate of deflated HTML

	char *block = new char[newsize];
	block[0] = '\0';

	char *temp = NULL;

	off_t bytesgot = 0;
	int err;

	z_stream d_stream;
	d_stream.zalloc = (alloc_func) 0;
	d_stream.zfree = (free_func) 0;
	d_stream.opaque = (voidpf) 0;
	d_stream.next_in = (Bytef *) data;
	d_stream.avail_in = buffer_length;
	d_stream.next_out = (Bytef *) block;
	d_stream.avail_out = newsize;

	// inflate either raw zlib, or possibly gzip with a header
	if (header) {
		err = inflateInit2(&d_stream, 15 + 32);
	} else {
		err = inflateInit2(&d_stream, -15);
	}

	if (err != Z_OK) {	// was a problem so just return
		delete[]block;  // don't forget to free claimed memory
#ifdef DGDEBUG
		std::cerr << "bad init inflate: " << err << std::endl;
#endif
		return;
	}
	while (true) {
#ifdef DGDEBUG
		std::cerr << "inflate loop" << std::endl;
#endif
		err = inflate(&d_stream, Z_SYNC_FLUSH);
		bytesgot = d_stream.total_out;
		if (err == Z_STREAM_END) {
			err = inflateEnd(&d_stream);
			if (err != Z_OK) {
				delete[] block;
#ifdef DGDEBUG
				std::cerr << "bad inflateEnd: " << d_stream.msg << std::endl;
#endif
				return;
			}
			break;
		}
		if (err != Z_OK) {	// was a problem so just return
			delete[]block;  // don't forget to free claimed memory
#ifdef DGDEBUG
			std::cerr << "bad inflate: " << d_stream.msg << std::endl;
#endif
			err = inflateEnd(&d_stream);
			if (err != Z_OK) {
#ifdef DGDEBUG
				std::cerr << "bad inflateEnd: " << d_stream.msg << std::endl;
#endif
			}
			return;
		}
		if (bytesgot > o.max_content_filter_size) {
			delete[]block;  // don't forget to free claimed memory
#ifdef DGDEBUG
			std::cerr << "inflated file larger than maxcontentfiltersize, not inflating further" << std::endl;
#endif
			err = inflateEnd(&d_stream);
			if (err != Z_OK) {
#ifdef DGDEBUG
				std::cerr << "bad inflateEnd: " << d_stream.msg << std::endl;
#endif
			}
			return;
		}

		// inflation is going ok, but we don't have enough room in the output buffer
		newsize = bytesgot * 2;
		temp = new char[newsize];
		memcpy(temp, block, bytesgot);
		delete[]block;
		block = temp;
		temp = NULL;

		d_stream.next_out = (Bytef *) (block + bytesgot);
		d_stream.avail_out = newsize - bytesgot;
	}

	compresseddata = data;
	compressed_buffer_length = buffer_length;
	buffer_length = bytesgot;
#ifdef DGDEBUG
	std::cout << "decompressed size: " << buffer_length << std::endl;
#endif
	data = new char[bytesgot+1];
	data[bytesgot] = '\0';
	memcpy(data, block, bytesgot);
	delete[] block;
}

// Does a regexp search and replace.
struct newreplacement
{
	int match;
	String replacement;
};
bool DataBuffer::contentRegExp(int filtergroup)
{

#ifdef DGDEBUG
	std::cout << "Starting content reg exp replace" << std::endl;
#endif
	bool contentmodified = false;
	unsigned int i;
	unsigned int j, k, m;
	unsigned int s = (*o.fg[filtergroup]).content_regexp_list_comp.size();
	unsigned int matches;
	unsigned int submatch, submatches;
	RegExp *re;
	String *replacement;
	unsigned int replen;
	int sizediff;
	char *newblock;
	char *dstpos;
	unsigned int srcoff;
	unsigned int nextoffset;
	unsigned int matchlen;

	std::queue<newreplacement*> matchqueue;

	for (i = 0; i < s; i++) {
		re = &((*o.fg[filtergroup]).content_regexp_list_comp[i]);
		if (re->match(data)) {
			replacement = &((*o.fg[filtergroup]).content_regexp_list_rep[i]);
			//replen = replacement->length();
			matches = re->numberOfMatches();

			sizediff = 0;
			m = 0;
			for (j = 0; j < matches; j++) {
				srcoff = re->offset(j);
				matchlen = re->length(j);

				// Count matches for ()'s
				for (submatches = 0; j+submatches+1 < matches; submatches++)
					if (re->offset(j+submatches+1) + re->length(j+submatches+1) > srcoff + matchlen)
						break;

				// \1 and $1 replacement
				
				// store match no. and default (empty) replacement string
				newreplacement* newrep = new newreplacement;
				newrep->match = j;
				newrep->replacement = "";
				// iterate over regex's replacement string
				for (k = 0; k < replacement->length(); k++) {
					// look for \1..\9 and $1..$9
					if (((*replacement)[k] == '\\' || (*replacement)[k] == '$') && (*replacement)[k+1] >= '1' && (*replacement)[k+1] <= '9') {
						// determine match number
						submatch = (*replacement)[++k] - '0';
						// add submatch contents to replacement string
						if (submatch <= submatches) {
							newrep->replacement += re->result(j + submatch).c_str();
						}
					} else {
						// unescape \\ and \$, and add other non-backreference characters
						if ((*replacement)[k] == '\\' && ((*replacement)[k+1] == '\\' || (*replacement)[k+1] == '$'))
							k++;
						newrep->replacement += replacement->subString(k, 1);
					}
				}
				matchqueue.push(newrep);

				// update size difference between original and modified content
				sizediff -= re->length(j);
				sizediff += newrep->replacement.length();
				// skip submatches to next top level match
				j += submatches;
				m++;
			}

			// now we know eventual size of content-replaced block, allocate memory for it
			newblock = new char[buffer_length + sizediff + 1];
			newblock[buffer_length + sizediff] = '\0';
			srcoff = 0;
			dstpos = newblock;
			matches = m;

#ifdef DGDEBUG
			std::cout << "content matches:" << matches << std::endl;
#endif
			// replace top-level matches using filled-out replacement strings
			newreplacement* newrep;
			for (j = 0; j < matches; j++) {
				newrep = matchqueue.front();
				nextoffset = re->offset(newrep->match);
				if (nextoffset > srcoff) {
					memcpy(dstpos, data + srcoff, nextoffset - srcoff);
					dstpos += nextoffset - srcoff;
					srcoff = nextoffset;
				}
				replen = newrep->replacement.length();
				memcpy(dstpos, newrep->replacement.toCharArray(), replen);
				dstpos += replen;
				srcoff += re->length(newrep->match);
				delete newrep;
				matchqueue.pop();
			}
			if (srcoff < buffer_length) {
				memcpy(dstpos, data + srcoff, buffer_length - srcoff);
			}
			delete[]data;
			data = newblock;
			buffer_length = buffer_length + sizediff;
			contentmodified = true;
		}
	}
	return contentmodified;
}
