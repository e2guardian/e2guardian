// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif
#include "DataBuffer.hpp"
#include "HTTPHeader.hpp"
#include "OptionContainer.hpp"
#include "Logger.hpp"

#include <sys/stat.h>
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

#define __E2HEADER_SENDALL 0
#define __E2HEADER_SENDFIRSTLINE 1
#define __E2HEADER_SENDREST 2

// GLOBALS

extern OptionContainer o;

// IMPLEMENTATION

DataBuffer::DataBuffer()
    : data(new char[1]), data_length(0)
{
    data[0] = '\0';
}

DataBuffer::DataBuffer(const void *indata, off_t length)     //not used! PIP
    : data(new char[length]), data_length(length)
{
    memcpy(data, indata, length);
}

void DataBuffer::reset()
{
    delete[] data;
    delete[] compresseddata;

    data = new char[1];
    data[0] = '\0';


    compresseddata = nullptr;
    data_length = 0;
    buffer_length = 0;
    compressed_buffer_data_length = 0;

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
    chunked = false;
    icap = false;
}

// delete the memory block when the class is destroyed
DataBuffer::~DataBuffer()
{
    delete[] data;
    if (compresseddata != nullptr) {
        delete[] compresseddata;
        compresseddata = nullptr;
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

void DataBuffer::set_current_config (FOptionContainer *newfgc) {
    fgc = newfgc;
}

//}
// swap back to a compressed version of the data, if one exists
// also delete uncompressed version
// if body was decompressed but not modified, this can save bandwidth
void DataBuffer::swapbacktocompressed()
{
    if (compresseddata != nullptr && compressed_buffer_data_length> 0) {
        delete[] data;
        data_length = compressed_buffer_data_length;
        data = compresseddata;

        compresseddata = nullptr;
        compressed_buffer_data_length = 0;
        DEBUG_network("Compressed data size ", data_length);
    }
}

int DataBuffer::readInFromSocket(Socket *sock, int size, bool wantall, int &result) {

    int rc;

    DEBUG_trace("size:", size, " wantall:", wantall);
    if (size < 1) {
        E2LOGGER_error("read request is negative");
        return -1;
    }

    if (wantall) {
            if (!swappedtodisk) {
                // if not swapped to disk and file is too large for RAM, then swap to disk
                if (data_length > o.content.max_content_ramcache_scan_size) {
                    DEBUG_debug("swapping to disk");
                    tempfilefd = getTempFileFD();
                    if (tempfilefd < 0) {
                        E2LOGGER_error("error buffering to disk so skipping disk buffering");
                        result = DB_TOBIG;
                        return -1;
                    }
                    write(tempfilefd, data, data_length);
                    swappedtodisk = true;
                    tempfilesize = data_length;
                }
            } else if (tempfilesize > o.content.max_content_filecache_scan_size) {
                // if swapped to disk and file too large for that too, then give up
                DEBUG_debug("defaultdm: file too big to be scanned, halting download");
                result = DB_TOBIG | DB_TOBIG_SCAN;
                return -1;
            }
        } else {
            if (data_length > o.content.max_content_filter_size) {
                // if we aren't downloading for virus scanning, and file too large for filtering, give up
                DEBUG_debug("defaultdm: file too big to be filtered, halting download");
                result = DB_TOBIG | DB_TOBIG_FILTER;
                return -1;
            }
        }

    DEBUG_debug("swappedtodisk:", swappedtodisk);
        if (!swappedtodisk) {
        if (size > (buffer_length - data_length)) {
            if(!increase_buffer(size - (buffer_length - data_length))) {
                size = (buffer_length - data_length);
            }
        }
            if (chunked) {
            DEBUG_debug("readChunk:", data_length, ",", size);
                rc = sock->readChunk((data + data_length), size, timeout);
            } else {
            DEBUG_debug("bufferReadFromSocket:", data_length, ",", size);
                rc = bufferReadFromSocket(sock, (data + data_length), size, timeout);
            }

            if (rc <= 0) {
                if (chunked)
                    got_all = true;
                return -1;
                // an error occurred so end the while()
                // or none received so pipe iis closed or chunking has ended
            } else {
                bytes_toget -= rc;
                data_length += rc;
                data[data_length] = '\0';
            }
        } else {
            if (chunked) {
                rc = sock->readChunk(data, buffer_length, timeout);
            } else {
                rc = bufferReadFromSocket(sock, data,
                        // if not getting everything until connection close, grab only what is left
                                             (!geteverything && (bytes_toget  < buffer_length) ? bytes_toget
                                                                                                    : buffer_length),
                                             timeout);
            }
            if (rc <= 0) {
                if (chunked)
                    got_all = true;
                result = 0;
                return 0;
            } else {
                bytes_toget  -= rc;
                write(tempfilefd, data, rc);
                tempfilesize += rc;
                DEBUG_debug("written to disk:", rc, " total:", tempfilesize);
            }
        }
        result = 0;
    DEBUG_debug("rc=", rc, " bytes_toget=", bytes_toget, " data_length=", data_length);
        return rc;
}

bool DataBuffer::increase_buffer(int extra) {
    int more = 65536;
    if (extra > more)
        more = extra;
    if ((buffer_length + more) > o.content.max_content_filter_size) {
        more = o.content.max_content_filter_size - buffer_length;
    }
    if (more > 0) {
        char *temp = new char[buffer_length + more + 1]; // replacement store
        temp[buffer_length + more] = '\0';
        memcpy(temp, data, data_length); // copy the current data
        delete[] data; // delete the current data block
        data = temp;
        temp = nullptr;
        buffer_length += more; // update data size counter
        DEBUG_debug("data buffer extended by ", more, " to ", buffer_length);
        return true;
    }
    return false;
}

// a much more efficient reader that does not assume the contents of
// the buffer gets filled thus reducing memcpy()ing and new()ing
int DataBuffer::bufferReadFromSocket(Socket *sock, char *buffer, int size, int sockettimeout)
{
        int pos = 0;
        int rc;
        while (pos < size) {
            rc = sock->readFromSocket(&buffer[pos], size - pos, 0, sockettimeout, true);
            if (rc < 1) {
                // none recieved or an error
                if (pos > 0) {
                    return pos; // some was recieved previous into buffer
                }
                return rc; // just return with the return code
            }
            pos += rc;
        }
        return size; // full buffer
}

// a much more efficient reader that does not assume the contents of
// the buffer gets filled thus reducing memcpy()ing and new()ing.
// in addition to the actual socket timeout, used for each individual read, this version
// incorporates a "global" timeout within which all reads must complete.
int DataBuffer::bufferReadFromSocket(Socket *sock, char *buffer, int size, int sockettimeout, int stimeout)
{
    DEBUG_trace("");
    int pos = 0;
    int rc;
    struct timeval starttime;
    struct timeval nowadays;
    gettimeofday(&starttime, NULL);
    while (pos < size) {
        if (chunked) {
            rc = sock->readChunk(&buffer[pos], size - pos,sockettimeout );
        } else {
            rc = sock->readFromSocket(&buffer[pos], size - pos, 0, sockettimeout, true);
        }
        if (rc < 1) {
            // none recieved or an error
            if (pos > 0) {
                return pos; // some was recieved previous into buffer
            }
            return rc; // just return with the return code
        }
        pos += rc;
        gettimeofday(&nowadays, NULL);
        if (nowadays.tv_sec - starttime.tv_sec > stimeout) {
            DEBUG_debug("buffered socket read more than timeout");
            return pos; // just return how much got so far then
        }
    }
    return size; // full buffer
}

// make a temp file and return its FD. only currently used in DM plugins.
int DataBuffer::getTempFileFD()
{
    if (tempfilefd > -1) {
        return tempfilefd;
    }
    tempfilepath = o.content.download_dir.c_str();
    tempfilepath += "/tfXXXXXX";
    char *tempfilepatharray = new char[tempfilepath.length() + 1];
    strcpy(tempfilepatharray, tempfilepath.toCharArray());
    umask(0007); // only allow access to e2g user and group
    if ((tempfilefd = mkstemp(tempfilepatharray)) < 0) {
        E2LOGGER_error("Could not create temp file to store download for scanning: ", strerror(errno));
        tempfilefd = -1;
        tempfilepath = "";
    } else {
        tempfilepath = tempfilepatharray;
    }
    delete[] tempfilepatharray;
    return tempfilefd;
}

// check the client's user agent, see if we have a DM plugin compatible with it, and use it to download the body of the given request
bool DataBuffer::in(Socket *sock, Socket *peersock, HTTPHeader *requestheader, HTTPHeader *docheader, bool runav, int *headersent,StoryBoard &story, NaughtyFilter *cm)
{
    //Socket *sock = where to read from
    //Socket *peersock = browser to send stuff to for keeping it alive
    //HTTPHeader *requestheader = header client used to request
    //HTTPHeader *docheader = header used for sending first line of reply
    //bool runav = to determine if limit is av or not
    //int *headersent = to use to send the first line of header if needed
    //				  or to mark that the header has already been sent

    // so we know if we only partially downloaded from
    // upstream so later, if allowed, we can send the rest
    bool toobig = false;

    // match request to download manager so browsers potentially can have a prettier version
    // and software updates, stream clients, etc. can have a compatible version.
    //int rc = 0;
    int j = 0;
 //   int rc = -1;
    DEBUG_trace("");
    for (std::deque<Plugin *>::iterator i = o.plugins.dmplugins_begin; i != o.plugins.dmplugins_end; i++) {
        ++j;
        if ((i + 1) == o.plugins.dmplugins_end) {
            DEBUG_debug("Got to final download manager so defaulting to always match.");
            dm_plugin = (DMPlugin *)(*i);
            dm_plugin->in(this, sock, peersock, requestheader, docheader, runav, headersent, &toobig);
            break;
        } else {
            dm_plugin = (DMPlugin *)(*i);
            if (story.runFunctEntry(dm_plugin->story_entry, *cm)) {
                DEBUG_debug("Matching download manager number: ", j);
                dm_plugin->in(this, sock, peersock, requestheader, docheader, runav, headersent, &toobig);
                break;
            }
        }
        j++;
    }
    return toobig;
}

// send the request body to the client after having been handled by a DM plugin
bool DataBuffer::out(Socket *sock)
{
    if (dontsendbody) {
        DEBUG_debug("dontsendbody true; not sending");
        return true;
    }
  //  if (!(*sock).readyForOutput(timeout)) return false; // exceptions on timeout or error

    DEBUG_trace("");
    if (tempfilefd > -1) {
        // must have been too big for ram so stream from disk in blocks
        DEBUG_debug("Sending ", tempfilesize - bytesalreadysent, " bytes from temp file (", bytesalreadysent, " already sent)");;
        off_t sent = bytesalreadysent;
        int rc;

        if (lseek(tempfilefd, bytesalreadysent, SEEK_SET) < 0)
            return false;
         int block_len;
        if(chunked)
            block_len = 4048;
        else
            block_len = data_length;

        while (sent < tempfilesize) {
            rc = read(tempfilefd, data, block_len);
            DEBUG_debug("reading temp file rc:", rc);
            if (rc < 0) {
                DEBUG_debug("error reading temp file so throwing exception");
                return false;
            }
            if (rc == 0) {
                DEBUG_debug("got zero bytes reading temp file");
                break; // should never happen
            }
            // as it's cached to disk the buffer must be reasonably big
            if(chunked) {
                if (!sock->writeChunk(data, rc, timeout))
                    return false;
            } else {
                if (!sock->writeToSocket(data, rc, 0, timeout)) {
                    return false;
                }
            }
            sent += rc;
            DEBUG_debug("total sent from temp:", sent);
        }
        if (chunked && got_all) {
            String n;
            if (!sock->writeChunkTrailer(n))
                return false;
        }
        close(tempfilefd);
        tempfilefd = -1;
        tempfilesize = 0;
        unlink(tempfilepath.toCharArray());
    } else {
        off_t sent = bytesalreadysent;
        DEBUG_debug("Sending ", data_length, " bytes from RAM (", buffer_length, " in buffer; ", bytesalreadysent, " already sent)" );
        // it's in RAM, so just send it, no streaming from disk
        int block_len;
        if(chunked)
            block_len = 4048;
        else
            block_len = data_length;

        if (data_length != 0) {
            while (sent < data_length) {
                if( block_len > (data_length - sent))
                    block_len = (data_length - sent);
                if (chunked) {
                    if (!sock->writeChunk(data + sent, block_len, timeout)) {
                        DEBUG_network("writeChunk failed after ", sent, " bytes");
                        return false;
                    }

                } else {
                    if (!sock->writeToSocket(data + sent, data_length - sent, 0, timeout))
                        return false;
                }
                sent += block_len;
            }
            //if (chunked && got_all)
            if (chunked ) {
                String n;
                if (!sock->writeChunkTrailer(n))
                    return false;
            }
        } else {
            if(chunked) {
                if (!sock->writeChunk(data + bytesalreadysent, 0, timeout))
                    return false;
            } else {
                if (!sock->writeToSocket("\r\n\r\n", 4, 0, timeout))
                    return false;
            }
        }
        DEBUG_debug("Sent ", buffer_length - bytesalreadysent," bytes from RAM (", buffer_length);
    }
    return true;
}

// zlib decompression
void DataBuffer::zlibinflate(bool header)
{
    if (data_length < 12) {
        return; // it can't possibly be zlib'd
    }
    DEBUG_debug("compressed size:", data_length);

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

    int newsize = data_length * 5; // good estimate of deflated HTML

    char *block = new char[newsize];
    block[0] = '\0';

    char *temp = NULL;

    off_t bytesgot = 0;
    int err;

    z_stream d_stream;
    d_stream.zalloc = (alloc_func)0;
    d_stream.zfree = (free_func)0;
    d_stream.opaque = (voidpf)0;
    d_stream.next_in = (Bytef *)data;
    d_stream.avail_in = data_length;
    d_stream.next_out = (Bytef *)block;
    d_stream.avail_out = newsize;

    // inflate either raw zlib, or possibly gzip with a header
    if (header) {
        err = inflateInit2(&d_stream, 15 + 32);
    } else {
        err = inflateInit2(&d_stream, -15);
    }

    if (err != Z_OK) { // was a problem so just return
        delete[] block; // don't forget to free claimed memory
        DEBUG_debug("bad init inflate: ", err);
        return;
    }
    while (true) {
        DEBUG_debug("inflate loop");
        err = inflate(&d_stream, Z_SYNC_FLUSH);
        bytesgot = d_stream.total_out;
        if (err == Z_STREAM_END) {
            err = inflateEnd(&d_stream);
            if (err != Z_OK) {
                delete[] block;
                DEBUG_debug("bad inflateEnd: ", d_stream.msg);
                return;
            }
            break;
        }
        if (err != Z_OK) { // was a problem so just return
            delete[] block; // don't forget to free claimed memory
            DEBUG_debug("bad inflate: ", d_stream.msg);
            err = inflateEnd(&d_stream);
            if (err != Z_OK) {
                DEBUG_debug("bad inflateEnd: ", d_stream.msg);
            }
            return;
        }
        if (bytesgot > o.content.max_content_filter_size) {
            delete[] block; // don't forget to free claimed memory
            DEBUG_debug("inflated file larger than maxcontentfiltersize, not inflating further");
            err = inflateEnd(&d_stream);
            if (err != Z_OK) {
                DEBUG_debug("bad inflateEnd: ", d_stream.msg);
            }
            return;
        }

        // inflation is going ok, but we don't have enough room in the output buffer
        newsize = bytesgot * 2;
        temp = new char[newsize];
        memcpy(temp, block, bytesgot);
        delete[] block;
        block = temp;
        temp = NULL;

        d_stream.next_out = (Bytef *)(block + bytesgot);
        d_stream.avail_out = newsize - bytesgot;
    }

    compresseddata = data;
    compressed_buffer_data_length = data_length;  // change from buffer_length
    buffer_length = bytesgot;
    DEBUG_debug("decompressed size: ", data_length);
    data = new char[bytesgot + 1];
    data[bytesgot] = '\0';
    memcpy(data, block, bytesgot);
    delete[] block;
}

// Does a regexp search and replace.
struct newreplacement {
    int match;
    String replacement;
};
bool DataBuffer::contentRegExp(FOptionContainer* &foc)
{

    DEBUG_debug("Starting content reg exp replace");
    bool contentmodified = false;
    unsigned int i;
    unsigned int j, k, m;
    unsigned int s = (*foc).content_regexp_list_comp.size();
    unsigned int matches;
    unsigned int submatch, submatches;
    RegExp *re;
    RegResult Rre;
    String *replacement;
    unsigned int replen;
    int sizediff;
    char *newblock;
    char *dstpos;
    unsigned int srcoff;
    unsigned int nextoffset;
    unsigned int matchlen;

    std::queue<newreplacement *> matchqueue;

    for (i = 0; i < s; i++) {
        re = &((*foc).content_regexp_list_comp[i]);
        if (re->match(data, Rre)) {
            replacement = &((*foc).content_regexp_list_rep[i]);
            //replen = replacement->length();
            matches = Rre.numberOfMatches();

            sizediff = 0;
            m = 0;
            for (j = 0; j < matches; j++) {
                srcoff = Rre.offset(j);
                matchlen = Rre.length(j);

                // Count matches for ()'s
                for (submatches = 0; j + submatches + 1 < matches; submatches++)
                    if (Rre.offset(j + submatches + 1) + Rre.length(j + submatches + 1) > srcoff + matchlen)
                        break;

                // \1 and $1 replacement

                // store match no. and default (empty) replacement string
                newreplacement *newrep = new newreplacement;
                newrep->match = j;
                newrep->replacement = "";
                // iterate over regex's replacement string
                for (k = 0; k < replacement->length(); k++) {
                    // look for \1..\9 and $1..$9
                    if (((*replacement)[k] == '\\' || (*replacement)[k] == '$') && (*replacement)[k + 1] >= '1' && (*replacement)[k + 1] <= '9') {
                        // determine match number
                        submatch = (*replacement)[++k] - '0';
                        // add submatch contents to replacement string
                        if (submatch <= submatches) {
                            newrep->replacement += Rre.result(j + submatch).c_str();
                        }
                    } else {
                        // unescape \\ and \$, and add other non-backreference characters
                        if ((*replacement)[k] == '\\' && ((*replacement)[k + 1] == '\\' || (*replacement)[k + 1] == '$'))
                            k++;
                        newrep->replacement += replacement->subString(k, 1);
                    }
                }
                matchqueue.push(newrep);

                // update size difference between original and modified content
                sizediff -= Rre.length(j);
                sizediff += newrep->replacement.length();
                // skip submatches to next top level match
                j += submatches;
                m++;
            }

            // now we know eventual size of content-replaced block, allocate memory for it
            newblock = new char[data_length + sizediff + 1];
            newblock[data_length + sizediff] = '\0';
            srcoff = 0;
            dstpos = newblock;
            matches = m;

            DEBUG_debug("content matches:", matches);
            // replace top-level matches using filled-out replacement strings
            newreplacement *newrep;
            for (j = 0; j < matches; j++) {
                newrep = matchqueue.front();
                nextoffset = Rre.offset(newrep->match);
                if (nextoffset > srcoff) {
                    memcpy(dstpos, data + srcoff, nextoffset - srcoff);
                    dstpos += nextoffset - srcoff;
                    srcoff = nextoffset;
                }
                replen = newrep->replacement.length();
                memcpy(dstpos, newrep->replacement.toCharArray(), replen);
                dstpos += replen;
                srcoff += Rre.length(newrep->match);
                delete newrep;
                matchqueue.pop();
            }
            if (srcoff < data_length) {
                memcpy(dstpos, data + srcoff, data_length - srcoff);
            }
            delete[] data;
            data = newblock;
            data_length = data_length + sizediff;
            contentmodified = true;
        }
    }
    return contentmodified;
}

void DataBuffer::setChunked(bool ch = true) {
    chunked = ch;
    return;
}

void DataBuffer::setICAP(bool ch = true) {
    chunked = ch;
    icap = ch;
    return;
}
