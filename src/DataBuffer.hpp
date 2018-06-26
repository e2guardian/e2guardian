// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_DATABUFFER
#define __HPP_DATABUFFER

#include <exception>
#include <memory>
#include <string.h>
#include "Socket.hpp"
#include "String.hpp"
#include "FDFuncs.hpp"
#include "FOptionContainer.hpp"

class DMPlugin;

class DataBuffer
{
    public:
    char *data;
    off_t buffer_length;
    char *compresseddata= nullptr;
    off_t compressed_buffer_length = 0;
    off_t tempfilesize = 0;
    String tempfilepath;
    bool dontsendbody = false; // used for fancy download manager for example
    bool chunked = false;
    bool icap = false;
    bool got_all = false;   // used with chunked it all read-in
    int tempfilefd = -1;

    // the download manager we used during the last "in"
    DMPlugin *dm_plugin;

    DataBuffer();
    DataBuffer(const void *indata, off_t length);
    ~DataBuffer();

    int length()
    {
        return buffer_length;
    };

    void copyToMemory(char *location)
    {
        memcpy(location, data, buffer_length);
    };

    // read body in from proxy
    // gives true if it pauses due to too much data
    bool in(Socket *sock, Socket *peersock, class HTTPHeader *requestheader, class HTTPHeader *docheader, bool runav, int *headersent);
    // send body to client
    bool out(Socket *sock); //throw(std::exception);

    void setTimeout(int t)
    {
        timeout = t;
        stimeout = t / 1000;
    };
    void setDecompress(String d)
    {
        decompress = d;
    };

    // swap back to compressed version of body data (if data was decompressed but not modified; saves bandwidth)
    void swapbacktocompressed();

    // content regexp search and replace
    bool contentRegExp(FOptionContainer* &foc);

    // create a temp file and return its FD	- NOT a simple accessor function
    int getTempFileFD();

    void setChunked(bool ch);
    void setICAP(bool ch);

    void reset();

    private:
    // DM plugins do horrible things to our innards - this is acceptable pending a proper cleanup
    friend class DMPlugin;
    friend class dminstance;
#ifdef ENABLE_FANCYDM
    friend class fancydm;
#endif
#ifdef ENABLE_TRICKLEDM
    friend class trickledm;
#endif

    int timeout = 20000;  // in msecs
    int stimeout = 20;   // in secs
    off_t bytesalreadysent = 0;
    bool preservetemp = false;

    String decompress;

    void zlibinflate(bool header);

    // buffered socket reads - one with an extra "global" timeout within which all individual reads must complete
    int bufferReadFromSocket(Socket *sock, char *buffer, int size, int sockettimeout);
    int bufferReadFromSocket(Socket *sock, char *buffer, int size, int sockettimeout, int timeout);
};

#endif
