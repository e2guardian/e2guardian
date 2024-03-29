// For all support, instructions and copyright go to:
// http://e2guardian.org/
// Released under the GPL v2, with the OpenSSL exception described in the README file.

// INCLUDES

#ifdef HAVE_CONFIG_H
#include "e2config.h"
#endif

#include <cstddef>
#include <vector>
#include <string>
#include <exception>
#include <stdexcept>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <ctime>

#include <unistd.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "BackedStore.hpp"
#include "Logger.hpp"


// IMPLEMENTATION

BackedStore::BackedStore(size_t _ramsize, size_t _disksize, const char *_tempdir)
    : fd(-1), length(0), filename(NULL), ramsize(_ramsize), disksize(_disksize), tempdir(_tempdir), map(MAP_FAILED)
{
}

BackedStore::~BackedStore()
{
    if (map != MAP_FAILED)
        munmap(map, length);

    if (fd >= 0) {
        DEBUG_debug("BackedStore: closing & deleting temp file ", filename, " BAE2ERS!");
        int rc = 0;
        do {
            rc = close(fd);
        } while (rc < 0 && errno == EINTR);
        if (rc < 0)
            DEBUG_debug("BackedStore: cannot close temp file fd: ", strerror(errno));
        rc = unlink(filename);
        if (rc < 0)
            DEBUG_debug("BackedStore: cannot delete temp file: ", strerror(errno));
        free(filename);
    }
}

bool BackedStore::append(const char *data, size_t len)
{
    if (fd < 0) {
        DEBUG_debug("BackedStore: appending to RAM");
        // Temp file not yet opened - try to write to RAM
        if (rambuf.size() + len > ramsize) {
            // Would exceed RAM threshold
            if (rambuf.size() + len > disksize) {
                // Would also exceed disk threshold
                // - give up
                DEBUG_debug("BackedStore: data would exceed both RAM and disk thresholds");
                return false;
            }

            DEBUG_debug("BackedStore: data would exceed RAM threshold; dumping RAM to disk");

            // Open temp file, dump current data in there,
            // leave code below this if{} to write current
            // data to the file as well
            std::string filename_str = tempdir + "/__dgbsXXXXXX";
            filename = const_cast<char *>(filename_str.c_str());
            DEBUG_debug("BackedStore: filename template: ", filename);
            //	mode_t mask = umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP); // this mask is reversed
            umask(0007); // only allow access to e2g user and group
            if ((fd = mkstemp(filename)) < 0) {
                std::ostringstream ss;
                ss << thread_id << "BackedStore could not create temp file: " << strerror(errno);
                free(filename);
                throw std::runtime_error(ss.str().c_str());
            }

            DEBUG_debug("BackedStore: filename: ", filename);
            free(filename);

            size_t bytes_written = 0;
            ssize_t rc = 0;
            do {
                rc = write(fd, &(rambuf.front()) + bytes_written, rambuf.size() - bytes_written);
                if (rc > 0)
                    bytes_written += rc;
            } while (bytes_written < rambuf.size() && (rc > 0 || errno == EINTR));
            if (rc < 0 && errno != EINTR) {
                std::ostringstream ss;
                ss << thread_id << "BackedStore could not dump RAM buffer to temp file: " << strerror(errno);
                throw std::runtime_error(ss.str().c_str());
            }
            length = rambuf.size();
            rambuf.clear();
        } else
            rambuf.insert(rambuf.end(), data, data + len);
    }

    if (fd >= 0) {
        DEBUG_debug("BackedStore: appending to disk");
        // Temp file opened - try to write to disk
        if (map != MAP_FAILED)
            throw std::runtime_error("BackedStore could not append to temp file: store already finalised");
        if (len + length > disksize) {
            DEBUG_debug("BackedStore: data would exceed disk threshold");
            return false;
        }
        size_t bytes_written = 0;
        ssize_t rc = 0;
        do {
            rc = write(fd, data + bytes_written, len - bytes_written);
            if (rc > 0)
                bytes_written += rc;
        } while (bytes_written < len && (rc > 0 || errno == EINTR));
        if (rc < 0 && errno != EINTR) {
            std::ostringstream ss;
            ss << thread_id << "BackedStore could not dump RAM buffer to temp file: " << strerror(errno);
            throw std::runtime_error(ss.str().c_str());
        }
        length += len;
    }

    DEBUG_debug("BackedStore: finished appending");

    return true;
}

size_t BackedStore::getLength() const
{
    if (fd >= 0)
        return length;
    else
        return rambuf.size();
}

void BackedStore::finalise()
{
    if (fd < 0)
        // No temp file - nothing to finalise
        return;

    lseek(fd, 0, SEEK_SET);
    map = mmap(0, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        std::ostringstream ss;
        ss << thread_id << "BackedStore could not mmap() temp file: " << strerror(errno);
        throw std::runtime_error(ss.str().c_str());
    }
}

const char *BackedStore::getData() const
{
    if (fd < 0) {
        DEBUG_debug("BackedStore: returning pointer to RAM");
        return &(rambuf.front());
    } else {
        DEBUG_debug("BackedStore: returning pointer to mmap-ed file");
        if (map == MAP_FAILED)
            throw std::runtime_error("BackedStore could not return data pointer: store not finalised");
        return (const char *)map;
    }
}

std::string BackedStore::store(const char *prefix)
{
    if (fd >= 0) {
        // We already have a temp file on disk
        // Try creating a hardlink with the new name and see what happens
        std::ostringstream storedname;
        storedname << prefix;
        timeval tv;
        // Use time of day (in microsecond resolution) to try and generate
        // a "random" name for the hardlink - tempnam doesn't allow arbitrary
        // prefixes (POSIX says up to 5 chars).
        gettimeofday(&tv, NULL);
        storedname << '-' << tv.tv_sec << tv.tv_usec << std::flush;

        char *name = strrchr(filename, '/');
//        DEBUG_debug("BackedStore: creating hard link: " << (char)storedname );
        std::string storedname_str(storedname.str());
        int rc = link(name, storedname_str.c_str());
        if (rc >= 0)
            // Success!  Return new filename
            return storedname_str;
        else if (errno != EXDEV) {
            // Failure - but ignore EXDEV, as we can "recover"
            // from that by taking a different approach
            std::ostringstream ss;
            ss << thread_id << "BackedStore could not create link to existing temp file: " << strerror(errno);
            throw std::runtime_error(ss.str().c_str());
        }
    }

    // We don't already have a temp file,
    // or a simple link wasn't sufficient (EXDEV)
    // Generate a new filename in the given directory, with the given name prefix
    // Include timestamp in the name for added uniqueness
    std::ostringstream timedprefix;
    timedprefix << prefix << '-' << time(NULL) << '-' << std::flush;
    std::string storedname_str(timedprefix.str() + "XXXXXX");
    char *storedname = const_cast<char *>(storedname_str.c_str());
    DEBUG_debug("BackedStore: storedname template: ", storedname);
    int storefd;
    umask(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if ((storefd = mkstemp(storedname)) < 0) {
        std::ostringstream ss;
        ss << thread_id << "BackedStore could not create stored file: " << strerror(errno);
        throw std::runtime_error(ss.str().c_str());
    }
    DEBUG_debug("BackedStore: storedname: ", storedname);

    // Dump the RAM buffer/mmap-ed file contents to disk in the new location
    if (fd >= 0 && map == MAP_FAILED)
        throw std::runtime_error("BackedStore could not copy existing temp file: store not finalised");

    size_t bytes_written = 0;
    ssize_t rc = 0;
    if (fd >= 0) {
        do {
            rc = write(storefd, (const char *)map + bytes_written, length - bytes_written);
            if (rc > 0)
                bytes_written += rc;
        } while (bytes_written < length && (rc > 0 || errno == EINTR));
    } else {
        do {
            rc = write(storefd, &(rambuf.front()) + bytes_written, rambuf.size() - bytes_written);
            if (rc > 0)
                bytes_written += rc;
        } while (bytes_written < rambuf.size() && (rc > 0 || errno == EINTR));
    }

    if (rc < 0 && errno != EINTR) {
        std::ostringstream ss;
        ss << thread_id << "BackedStore could not dump RAM buffer to temp file: " << strerror(errno);
        do {
            rc = close(storefd);
        } while (rc < 0 && errno == EINTR);
        throw std::runtime_error(ss.str().c_str());
    }

    do {
        rc = close(storefd);
    } while (rc < 0 && errno == EINTR);

    return storedname;
}
