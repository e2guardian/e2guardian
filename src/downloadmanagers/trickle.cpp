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

#include <string.h>
#include <syslog.h>
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
#ifdef E2DEBUG
    std::cout << "Creating trickle DM" << std::endl;
#endif
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

    OptionContainer::SB_entry_map sen;
    sen.entry_function = cv["story_function"];
    if (sen.entry_function.length() > 0) {
        sen.entry_id = ENT_STORYB_DM_TRICKLE;
        story_entry = sen.entry_id;
        o.dm_entry_dq.push_back(sen);
        return 0;
    } else {
        if (!is_daemonised)
            std::cerr << thread_id << "No story_function defined in trickle DM plugin config" << std::endl;
        syslog(LOG_ERR, "No story_function defined in trickle DM plugin config");
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

#ifdef E2DEBUG
    std::cout << "Inside trickle download manager plugin" << std::endl;
#endif

    //  To access settings for the plugin use the following example:
    //      std::cout << "cvtest:" << cv["dummy"] << std::endl;

    //int rc = 0;
    d->bytesalreadysent = 0;
    d->bytes_toget = docheader->contentLength();

    if (!d->icap) {
#ifdef E2DEBUG
        std::cerr << thread_id << "tranencodeing is " << docheader->transferEncoding() << std::endl;
#endif
        d->chunked = docheader->transferEncoding().contains("chunked");
    }

#ifdef E2DEBUG
    std::cerr << thread_id << "bytes remaining is " << d->bytes_toget << std::endl;
#endif
    // if using non-persistent connections, some servers will not report
    // a content-length. in these situations, just download everything.
    d->geteverything = false;
    if ((d->bytes_toget  < 0) || (d->chunked))
        d->geteverything = true;

    d->swappedtodisk = false;
    d->doneinitialdelay = false;

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
#ifdef E2DEBUG
    std::cout << "blocksize: " << blocksize << std::endl;
#endif

    while ((d->bytes_toget > 0) || d->geteverything) {
        // send keep-alive bytes here
        if (o.trickle_delay > 0) {
            themdays.tv_sec = nowadays.tv_sec;
            d->doneinitialdelay = true;
            if ((*headersent) < 1) {
#ifdef E2DEBUG
                std::cout << "sending header first" << std::endl;
#endif
                docheader->out(NULL, peersock, __E2HEADER_SENDALL);
                (*headersent) = 2;
            }
            if (!d->swappedtodisk) {
                // leave a kilobyte "barrier" so the whole file does not get sent before scanning
                if ((d->data_length > 1024) && (d->bytesalreadysent < (d->data_length - 1024))) {
#ifdef E2DEBUG
                    std::cout << "trickle delay - sending a byte from the memory buffer" << std::endl;
#endif
                    peersock->writeToSocket(d->data + (d->bytesalreadysent++), 1, 0, d->timeout);
                }
#ifdef E2DEBUG
                else
                    std::cout << "trickle delay - no unsent bytes remaining! (memory)" << std::endl;
#endif
            } else {
                // check the file is at least one kilobyte ahead of our send pointer, so
                // the whole file does not get sent before scanning
                if (lseek(d->tempfilefd, d->bytesalreadysent + 1024, SEEK_SET) != (off_t) -1) {
               //    ssize_t bytes_written; //new just remove GCC warning
                    lseek(d->tempfilefd, d->bytesalreadysent, SEEK_SET);
#ifdef E2DEBUG
                    std::cout << "trickle delay - sending a byte from the file" << std::endl;
#endif
                    char byte;
                 //   bytes_written = read(d->tempfilefd, &byte, 1);
                    peersock->writeToSocket(&byte, 1, 0, d->timeout);
                    d->bytesalreadysent++;
                }
#ifdef E2DEBUG
                else
                    std::cout << "trickle delay - no unsent bytes remaining! (file)" << std::endl;
#endif
            }
        }

        int read_res;
        int rc;
        int bsize = blocksize;
        if ((!d->geteverything) && (d->bytes_toget < bsize))
            bsize = d->bytes_toget;
        std::cerr << thread_id << "bsize is " << bsize << std::endl;

        rc = d->readInFromSocket(sock, bsize, wantall, read_res);
        if (read_res & DB_TOBIG)
            *toobig = true;
        if (rc <= 0) break;
    }

    if (!(*toobig) && !d->swappedtodisk) { // won't deflate stuff swapped to disk
        if (d->decompress.contains("deflate")) {
#ifdef E2DEBUG
            std::cout << "zlib format" << std::endl;
#endif
            d->zlibinflate(false); // incoming stream was zlib compressed
        } else if (d->decompress.contains("gzip")) {
#ifdef E2DEBUG
            std::cout << "gzip format" << std::endl;
#endif
            d->zlibinflate(true); // incoming stream was gzip compressed
        }
    }
#ifdef E2DEBUG
    std::cout << "Leaving trickle download manager plugin" << std::endl;
#endif
    return 0;
}
