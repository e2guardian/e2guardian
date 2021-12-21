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
#include "FOptionContainer.hpp"
//#include "LOptionContainer.hpp"
#include "StoryBoard.hpp"

#define DB_TOBIG 1
#define DB_TOBIG_SCAN 2
#define DB_TOBIG_FILTER 4

class DMPlugin;

class DataBuffer
{
    public:
    char *data;
    off_t data_length = 0;
    off_t buffer_length = 0;
    char *compresseddata= nullptr;
    off_t compressed_buffer_data_length = 0;
    off_t tempfilesize = 0;
    String tempfilepath;
    bool dontsendbody = false; // used for fancy download manager for example
    bool chunked = false;
    bool icap = false;
    bool got_all = false;   // used with chunked it all read-in
    int tempfilefd = -1;

 //   std::shared_ptr<LOptionContainer> ldl;
         FOptionContainer *fgc;

    // the download manager we used during the last "in"
    DMPlugin *dm_plugin;

    DataBuffer();
    DataBuffer(const void *indata, off_t length);
    ~DataBuffer();

    bool increase_buffer(int extra);
    void set_current_config (FOptionContainer *newfgc);

    int length()
    {
        return data_length;
    };

    void copyToMemory(char *location)
    {
        memcpy(location, data, data_length);
    };

    // read body in from proxy
    // gives true if it pauses due to too much data
    bool in(Socket *sock, Socket *peersock, class HTTPHeader *requestheader, class HTTPHeader *docheader, bool runav, int *headersent, StoryBoard &story, NaughtyFilter *cm);
    // send body to client
    bool out(Socket *sock);

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
    friend class fancydm;
    friend class trickledm;

    int timeout = 20000;  // in msecs
    int stimeout = 20;   // in secs
    off_t bytesalreadysent = 0;
    off_t bytes_toget = 0;
    bool geteverything = false;
    bool swappedtodisk = false;
    bool doneinitialdelay = false;
    bool preservetemp = false;

    String decompress;

    void zlibinflate(bool header);

    int readInFromSocket(Socket *sock, int size, bool wantall, int &result);

    // buffered socket reads - one with an extra "global" timeout within which all individual reads must complete
    int bufferReadFromSocket(Socket *sock, char *buffer, int size, int sockettimeout);
    int bufferReadFromSocket(Socket *sock, char *buffer, int size, int sockettimeout, int timeout);
};

#endif
