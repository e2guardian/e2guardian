// Trickle download manager - sends parts of a file being downloaded, a byte
// at a time.
// WARNING: Files which are/can be processed before they are complete - such
// as certain image formats, shell scripts, and multimedia files - MAY have a
// working, malicious portion sent to the browser before scanning has
// completed!

// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES
#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include "../DownloadManager.hpp"
#include "../OptionContainer.hpp"
#include "../Logger.hpp"

#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

// GLOBALS

extern OptionContainer o;
extern thread_local std::string thread_id;
extern bool is_daemonised;

// DECLARATIONS

class trickledm : public DMPlugin
{
    public:
    trickledm(ConfigVar &definition)
        : DMPlugin(definition){};
    int in(DataBuffer *d, Socket *sock, Socket *peersock, HTTPHeader *requestheader,
        HTTPHeader *docheader, bool wantall, int *headersent, bool *toobig);
    int init(void *args);

};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

DMPlugin *trickledmcreate(ConfigVar &definition)
{
    DEBUG_trace("Creating trickle DM");
    return new trickledm(definition);
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

int trickledm::init(void *args)
{
    DMPlugin::init(args);

    StoryBoardOptions::SB_entry_map sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYB_DM_TRICKLE;
        story_entry = sen.entry_id;
        o.story.dm_entry_dq.push_back(sen);
        return 0;
    } else {
        E2LOGGER_error("No story_function defined in trickle DM plugin config");
        return -1;
    }
}

// download body for this request
int trickledm::in(DataBuffer *d, Socket *sock, Socket *peersock, class HTTPHeader *requestheader,
    class HTTPHeader *docheader, bool wantall, int *headersent, bool *toobig)
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

    DEBUG_trace("Inside trickle download manager plugin");

    //  To access settings for the plugin use the following example:
    //      std::cout << "cvtest:" << cv["dummy"] << std::endl;

    //int rc = 0;
    d->bytesalreadysent = 0;
    d->bytes_toget = docheader->contentLength();

    if (!d->icap) {
        DEBUG_dwload("tranencodeing is ", docheader->transferEncoding());
        d->chunked = docheader->transferEncoding().contains("chunked");
    }

    DEBUG_dwload("bytes remaining is ", d->bytes_toget);
    // if using non-persistent connections, some servers will not report
    // a content-length. in these situations, just download everything.
    d->geteverything = false;
    if ((d->bytes_toget  < 0) || (d->chunked))
        d->geteverything = true;

    d->swappedtodisk = false;
    d->doneinitialdelay = false;

   // struct timeval themdays;
   // struct timeval nowadays;
   // gettimeofday(&themdays, NULL);

    // buffer size for streaming downloads
    off_t blocksize = 32768;
    // set to a sensible minimum
    if (!wantall && (blocksize > o.content.max_content_filter_size))
        blocksize = o.content.max_content_filter_size;
    else if (wantall && (blocksize > o.content.max_content_ramcache_scan_size))
        blocksize = o.content.max_content_ramcache_scan_size;
    DEBUG_dwload("blocksize: ",  blocksize);

    while ((d->bytes_toget > 0) || d->geteverything) {
        // send keep-alive bytes here
        if (o.content.trickle_delay > 0) {
     //       themdays.tv_sec = nowadays.tv_sec;
            d->doneinitialdelay = true;
            if ((*headersent) < 1) {
                DEBUG_dwload("sending header first");
                docheader->out(NULL, peersock, __E2HEADER_SENDALL);
                (*headersent) = 2;
            }
            if (!d->swappedtodisk) {
                // leave a kilobyte "barrier" so the whole file does not get sent before scanning
                if ((d->data_length > 1024) && (d->bytesalreadysent < (d->data_length - 1024))) {
                    DEBUG_dwload("trickle delay - sending a byte from the memory buffer");
                    peersock->writeToSocket(d->data + (d->bytesalreadysent++), 1, 0, d->timeout);
                }
                else
                    DEBUG_dwload("trickle delay - no unsent bytes remaining! (memory)");
            
            } else {
                // check the file is at least one kilobyte ahead of our send pointer, so
                // the whole file does not get sent before scanning
                if (lseek(d->tempfilefd, d->bytesalreadysent + 1024, SEEK_SET) != (off_t) -1) {
               //    ssize_t bytes_written; //new just remove GCC warning
                    lseek(d->tempfilefd, d->bytesalreadysent, SEEK_SET);
                    DEBUG_dwload("trickle delay - sending a byte from the file");
                    char byte;
                 //   bytes_written = read(d->tempfilefd, &byte, 1);
                    peersock->writeToSocket(&byte, 1, 0, d->timeout);
                    d->bytesalreadysent++;
                }
                else
                    DEBUG_dwload("trickle delay - no unsent bytes remaining! (file)");
            }
        }

        int read_res;
        int rc;
        int bsize = blocksize;
        if ((!d->geteverything) && (d->bytes_toget < bsize))
            bsize = d->bytes_toget;
        DEBUG_dwload("bsize is ", bsize);

        rc = d->readInFromSocket(sock, bsize, wantall, read_res);
        if (read_res & DB_TOBIG)
            *toobig = true;
        if (rc <= 0) break;
    }

    if (!(*toobig) && !d->swappedtodisk) { // won't deflate stuff swapped to disk
        if (d->decompress.contains("deflate")) {
            DEBUG_dwload("zlib format");
            d->zlibinflate(false); // incoming stream was zlib compressed
        } else if (d->decompress.contains("gzip")) {
            DEBUG_dwload("gzip format");
            d->zlibinflate(true); // incoming stream was gzip compressed
        }
    }
    DEBUG_trace("Leaving trickle download manager plugin");
    return 0;
}
