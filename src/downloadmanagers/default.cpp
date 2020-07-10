// Default download manager, used when no other plugin matches the user agent

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

// DECLARATIONS

class dminstance : public DMPlugin {
public:
    dminstance(ConfigVar &definition)
            : DMPlugin(definition) {};

    int in(DataBuffer *d, Socket *sock, Socket *peersock, HTTPHeader *requestheader,
           HTTPHeader *docheader, bool wantall, int *headersent, bool *toobig);

    // default plugin is as basic as you can get - no initialisation, and uses the default
    // set of matching mechanisms. uncomment and implement these to override default behaviour.
    //int init(void* args);
    //bool willHandle(HTTPHeader *requestheader, HTTPHeader *docheader);
};

// IMPLEMENTATION

// class factory code *MUST* be included in every plugin

DMPlugin *defaultdmcreate(ConfigVar &definition) {
    e2logger_trace("Creating default DM");
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
int dminstance::in(DataBuffer *d, Socket *sock, Socket *peersock, class HTTPHeader *requestheader,
                   class HTTPHeader *docheader, bool wantall, int *headersent, bool *toobig) {

//DataBuffer *d = where to stick the data back into
//Socket *sock = where to read from
//Socket *peersock = browser to send stuff to for keeping it alive
//HTTPHeader *requestheader = header client used to request
//HTTPHeader *docheader = header used for sending first line of reply
//bool wantall = to determine if just content filter or a full scan
//int *headersent = to use to send the first line of header if needed
//                                or to mark the header has already been sent
//bool *toobig = flag to modify to say if it could not all be downloaded

    e2logger_trace("Inside default download manager plugin  icap=", d->icap);

    //  To access settings for the plugin use the following example:
    //      std::cerr << "cvtest:" << cv["dummy"] << std::endl;

   // int rc = 0;
    d->got_all = false;
    d->bytes_toget = docheader->contentLength();
    if (!d->icap) {
        e2logger_debug("tranencodeing is ", docheader->transferEncoding());
        d->chunked = docheader->transferEncoding().contains("chunked");
    }

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

    e2logger_debug("blocksize: ", blocksize);

    while ((d->bytes_toget  > 0) || d->geteverything) {
        e2logger_debug("toget:", d->bytes_toget, "geteverything", d->geteverything);
        // send x-header keep-alive here
        if (o.trickle_delay > 0) {
            gettimeofday(&nowadays, NULL);
            if (d->doneinitialdelay ? nowadays.tv_sec - themdays.tv_sec > o.trickle_delay :
                nowadays.tv_sec - themdays.tv_sec > o.initial_trickle_delay) {
                themdays.tv_sec = nowadays.tv_sec;
                d->doneinitialdelay = true;
                if ((*headersent) < 1) {
                    e2logger_debug("sending first line of header first");
                    if (!d->icap) {
                        docheader->out(NULL, peersock, __E2HEADER_SENDFIRSTLINE);
                        (*headersent) = 1;
                    }
                }
                e2logger_debug("trickle delay - sending X-E2KeepAlive: on");
                if (!d->icap)
                    peersock->writeString("X-E2GKeepAlive: on\r\n");
            }
        }
        int read_res;
        int rc;
        int bsize = blocksize;
        if((!d->geteverything) && (d->bytes_toget < bsize))
            bsize = d->bytes_toget;
        e2logger_debug("bsize is ", bsize);

        rc = d->readInFromSocket(sock,bsize,wantall, read_res);
        if(read_res & DB_TOBIG)
            *toobig = true;
        if (rc <= 0) break;
    }

    if (!(*toobig) && !d->swappedtodisk) { // won't deflate stuff swapped to disk
        if (d->decompress.contains("deflate")) {
            e2logger_debug("zlib format");
            d->zlibinflate(false); // incoming stream was zlib compressed
        } else if (d->decompress.contains("gzip")) {
            e2logger_debug("gzip format");
            d->zlibinflate(true); // incoming stream was gzip compressed
        }
    }
    d->bytesalreadysent = 0;
    e2logger_trace("Leaving default download manager plugin");
    return 0;
}
