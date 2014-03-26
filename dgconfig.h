/* dgconfig.h.  Generated from dgconfig.h.in by configure.  */
/* dgconfig.h.in.  Generated from configure.ac by autoheader.  */

/* Define to enable support for add header */
#define ADDHEADER 

/* Maximum number of open filedescriptors */
#define DANS_MAXFD 8096

/* Define to enable debug build mode */
/* #undef DGDEBUG */

/* Record configure-time options */
#define DG_CONFIGURE_OPTIONS " '--mandir=/usr/share/man/' '--with-proxyuser=dansguardian' '--with-proxygroup=dansguardian' '--prefix=/usr' '--mandir=${prefix}/share/man' '--infodir=${prefix}/share/info' '--sysconfdir=/etc' '--localstatedir=/var' '--enable-commandline=yes' '--enable-trickledm=yes' 'CXX=g++' 'CXXFLAGS=-g -O2' 'LDFLAGS=' 'CPPFLAGS=' 'CC=cc' 'CFLAGS=-g -O2' '--enable-email=no' '--enable-ntlm=no' '--enable-pcre=yes' '--with-filedescriptors=8096'"

/* Define to enable AvastD content scanner */
/* #undef ENABLE_AVASTD */

/* Define to enable ClamD content scanner */
/* #undef ENABLE_CLAMD */

/* Define to enable command-line content scanner */
#define ENABLE_COMMANDLINE /**/

/* Define to enable email reporting */
/* #undef ENABLE_EMAIL */

/* Define to enable fancy download manager */
#define ENABLE_FANCYDM /**/

/* Define to enable ICAP content scanner */
/* #undef ENABLE_ICAP */

/* Define to enable KAVD content scanner */
/* #undef ENABLE_KAVD */

/* Define to enable NTLM auth plugin */
/* #undef ENABLE_NTLM */

/* Define to enable original destination IP checking */
/* #undef ENABLE_ORIG_IP */

/* Define to enable backtrace on segmentation fault */
/* #undef ENABLE_SEGV_BACKTRACE */

/* Define to enable trickle download manager */
#define ENABLE_TRICKLEDM /**/

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the `backtrace' function. */
/* #undef HAVE_BACKTRACE */

/* Define to 1 if you have the <byteswap.h> header file. */
#define HAVE_BYTESWAP_H 1

/* Define to 1 if you have the `dup2' function. */
#define HAVE_DUP2 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `fork' function. */
#define HAVE_FORK 1

/* Define to 1 if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to 1 if you have the `iconv' function. */
/* #undef HAVE_ICONV */

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <limits.h> header file. */
#define HAVE_LIMITS_H 1

/* Define to 1 if you have the <locale.h> header file. */
#define HAVE_LOCALE_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the `memset' function. */
#define HAVE_MEMSET 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to enable PCRE support */
#define HAVE_PCRE /**/

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 if you have the `regcomp' function. */
/* #undef HAVE_REGCOMP */

/* Define to 1 if you have the `resolv' function. */
/* #undef HAVE_RESOLV */

/* Define to 1 if you have the `select' function. */
#define HAVE_SELECT 1

/* Define to 1 if you have the `seteuid' function. */
#define HAVE_SETEUID 1

/* Define to 1 if you have the `setgid' function. */
#define HAVE_SETGID 1

/* Define to 1 if you have the `setlocale' function. */
#define HAVE_SETLOCALE 1

/* Define to 1 if you have the `setreuid' function. */
#define HAVE_SETREUID 1

/* Define to 1 if you have the `setuid' function. */
#define HAVE_SETUID 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the `strerror' function. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `strstr' function. */
#define HAVE_STRSTR 1

/* Define to 1 if you have the `strtol' function. */
#define HAVE_STRTOL 1

/* Define to 1 if you have the <syslog.h> header file. */
#define HAVE_SYSLOG_H 1

/* Define to 1 if you have the <sys/poll.h> header file. */
#define HAVE_SYS_POLL_H 1

/* Define to 1 if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/un.h> header file. */
#define HAVE_SYS_UN_H 1

/* Define to 1 if you have the `umask' function. */
#define HAVE_UMASK 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to 1 if you have the `vfork' function. */
#define HAVE_VFORK 1

/* Define to 1 if you have the <vfork.h> header file. */
/* #undef HAVE_VFORK_H */

/* Define to 1 if `fork' works. */
#define HAVE_WORKING_FORK 1

/* Define to 1 if `vfork' works. */
#define HAVE_WORKING_VFORK 1

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to enable support for legacy log format */
/* #undef LEGACY_LOG */

/* Define to enable support for local lists */
/* #undef LOCAL_LISTS */

/* Define if type "off_t" is a typedef of another type for which String
   already has a constructor */
/* #undef OFFT_COLLISION */

/* Name of package */
#define PACKAGE "e2guardian"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "e2guardian"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "e2guardian 1.0.0.1"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "e2guardian"

/* Define to the version of this package. */
#define PACKAGE_VERSION "1.0.0.1  First Alpha release  -"

/* Define to enable DNS auth plugin */
/* #undef PRT_DNSAUTH */

/* Define to enable support for referer exceptions */
#define REFEREXCEPT 

/* Define to enable support for regexp redirects */
#define RXREDIRECTS 

/* Define to enable support for ssl extra lists */
#define SEARCHWORDS 

/* Define to enable support for ssl extra lists */
#define SSL_EXTRA_LISTS 

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define to enable support for total block list */
/* #undef TOTAL_BLOCK_LIST */

/* Version number of package */
#define VERSION "1.0.0.1"

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef gid_t */

/* Define to `long' if <sys/types.h> does not define. */
/* #undef off_t */

/* Define to `int' if <sys/types.h> does not define. */
/* #undef pid_t */

/* Define to `unsigned' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to `int' if <sys/types.h> doesn't define. */
/* #undef uid_t */

/* Define as `fork' if `vfork' does not work. */
/* #undef vfork */
