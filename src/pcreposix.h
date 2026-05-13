/*
 * Compatibility header: pcreposix.h
 *
 * Some parts of the codebase (or third-party code) expect the legacy
 * PCRE1 POSIX wrapper header <pcreposix.h>. On modern systems we may
 * only have libpcre2 and its POSIX wrapper <pcre2posix.h> available.
 *
 * This file is a tiny shim to allow code that includes <pcreposix.h>
 * to build when only libpcre2 (and the pcre2-posix wrapper) are
 * installed. It forwards to the PCRE2 POSIX header.
 *
 * Purpose:
 * - Provide compatibility across distributions with differing PCRE
 *   packaging (libpcre vs libpcre2).
 * - Make it explicit in-source why this shim exists for future readers.
 */

#ifndef PCREPOSIX_H
#define PCREPOSIX_H

#include <pcre2posix.h>

#endif /* PCREPOSIX_H */

