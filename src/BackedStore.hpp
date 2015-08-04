// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

#ifndef __HPP_BACKEDSTORE
#define __HPP_BACKEDSTORE

// Class into which data can be liberally shoved into RAM up to threshold
// A, then automagically stored on disk instead up to threshold B, then
// start failing (but with sensible errors).
class BackedStore
{
    public:
    // Constructor - pass in RAM & disk thresholds
    // and a directory path for temp files
    BackedStore(size_t _ramsize, size_t _disksize,
        const char *_tempdir = "/tmp");
    ~BackedStore();

    // Add data to the store - returns false if
    // disksize would be exceeded or store has
    // been finalised
    bool append(const char *data, size_t len);

    // Finalise the store - cannot append any more
    // data after this.  Needed because if we are
    // writing to a temp file, mmap is used to access
    // the data, which requires a known file length.
    void finalise();

    // Data access
    const char *getData() const;

    // Get length of buffer
    size_t getLength() const;

    // Store the contents of the buffer using the given
    // prefix to generate a unique filename.  Return the filename.
    std::string store(const char *prefix);

    private:
    // Buffer & file descriptor for in-memory/on-disk storage
    std::vector<char> rambuf;
    int fd;

    // Size of buffer/file
    size_t length;

    // Temp file name
    char *filename;

    // Thresholds
    size_t ramsize;
    size_t disksize;

    // Temp directory path
    std::string tempdir;

    // Pointer to mmapped file contents
    void *map;
};

#endif
