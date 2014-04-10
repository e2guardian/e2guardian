# Autoconf script
# Inspired by a script provided by Alex Ott
# 2004,2005 - Daniel Barron

AC_DEFINE([SEARCHWORDS],[""],[Define to enable search word checking])

AC_DEFINE([ADDHEADER],[""],[Define to enable insert http header function])

AC_DEFINE([REFEREXCEPT],[""],[Define to enable exceptions on http referer header])
AC_DEFINE([RXREDIRECTS],[""],[Define to enable browser redirects based on regexp])
AC_DEFINE([SSL_EXTRA_LISTS],[""],[Define to enable extra SSL lists ])
AC_DEFINE([TOTAL_BLOCK_LIST],[""],[Define to enable total block list via stdin])
AC_DEFINE([LOCAL_LISTS],[""],[Define to enable local lists which override main lists])
AC_DEFINE([FD_SETSIZE_OVERIDE],[""],[Define to allow DANS_MAXFD to exceed FD_SETSIZE])

AC_PREREQ(2.57)
AC_INIT(e2guardian, 3.0.1)
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([dgconfig.h])

AC_CACHE_LOAD

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_LANG(C++)

AC_CACHE_SAVE

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h])
AC_CHECK_HEADERS([string.h sys/socket.h sys/time.h syslog.h unistd.h locale.h])
AC_CHECK_HEADERS([sys/types.h sys/un.h sys/poll.h sys/resource.h])
AC_CHECK_HEADERS([pwd.h grp.h])
AC_CHECK_HEADERS([byteswap.h])

# Check system endianness
AC_C_BIGENDIAN

# check for zlib
AC_MSG_CHECKING(if zlib should be statically linked)
AC_ARG_ENABLE(static-zlib,
[AC_HELP_STRING([--enable-static-zlib@<:@=no@:>@], [Enable static linking of zlib])],
[ if test "x$enableval" = "xno"; then
staticzlib=false
AC_MSG_RESULT(no)
else
staticzlib=true
AC_MSG_RESULT(yes)
fi
],
[
staticzlib=false
AC_MSG_RESULT(no)
])

AC_MSG_CHECKING(for zlib)
AC_ARG_WITH(zlib,
[AC_HELP_STRING([--with-zlib@<:@=NONE@:>@], [non-standard search path for zlib library])],
[ # check for header & func (in library) in given prefix
CPPFLAGS="${CPPFLAGS} -I${withval}/include"
if test "x$staticzlib" = "xtrue"; then
LIBS="-Bstatic -L${withval} -lz -Bdynamic ${LIBS}"
else
LIBS="-L${withval}/lib -lz ${LIBS}"
fi
],
[ # if --with-zlib is not supplied, we still need -lz in LIBS.
if test "x$staticzlib" = "xtrue"; then
LIBS="-Bstatic -lz -Bdynamic ${LIBS}"
else
LIBS="-lz ${LIBS}"
fi
])
AC_CHECK_HEADERS([zlib.h])
if ! test "x$staticzlib" = "xtrue"; then
AC_CHECK_LIB(z, gzdopen, [AC_MSG_RESULT(yes)], [AC_MSG_ERROR([no zlib!])])
fi

AC_CACHE_SAVE

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_TYPE_UID_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([dup2 gettimeofday memset select])
AC_CHECK_FUNCS([strerror strstr strtol])
AC_CHECK_FUNCS([setuid setgid umask seteuid setreuid setlocale])
AC_SEARCH_LIBS([floor], [m])
AC_SEARCH_LIBS([gethostbyname], [nsl])
AC_SEARCH_LIBS([socket], [socket], [], [
AC_CHECK_LIB(
[socket], [socket], [LIBS="-lsocket -lnsl $LIBS"],
[], [-lnsl]
)
])
AC_SEARCH_LIBS([inet_aton], [resolv])

AC_CACHE_SAVE

AC_MSG_CHECKING(for backside with both hands)
AC_MSG_RESULT(no)
AC_MSG_CHECKING(build os)
AC_CANONICAL_BUILD
AC_MSG_RESULT($build_os)

AC_MSG_CHECKING(for debug option)
AC_ARG_WITH(dgdebug,
[AC_HELP_STRING([--with-dgdebug@<:@=off@:>@], [switch on debug build mode])],
[if test "x${withval}" == "xoff" ; then
  AC_MSG_RESULT(no)
else
  AC_MSG_RESULT(yes)
  dgdebug=${withval}
  AC_DEFINE(DGDEBUG, 1, [Define to enable debug build mode])
fi], [
  # disable by default
  AC_MSG_RESULT(no)
])


AC_MSG_CHECKING(for proxy user)
AC_ARG_WITH(proxyuser,
[AC_HELP_STRING([--with-proxyuser@<:@=nobody@:>@], [name of proxy user])],
[if test "x${withval}" != "x" ; then
  AC_MSG_RESULT(yes)
  proxyuser=${withval}
else
  AC_MSG_RESULT(no)
  proxyuser=nobody
fi], [
  # disable by default
  AC_MSG_RESULT(no)
  proxyuser=nobody
])
AC_SUBST(DGPROXYUSER, "$proxyuser")

AC_MSG_CHECKING(for proxy group)
AC_ARG_WITH(proxygroup,
[AC_HELP_STRING([--with-proxygroup@<:@=nobody@:>@], [name of proxy group])],
[if test "x${withval}" != "x" ; then
  AC_MSG_RESULT(yes)
  proxygroup=${withval}
else
  AC_MSG_RESULT(no)
  proxygroup=nobody
fi], [
  # disable by default
  AC_MSG_RESULT(no)
  proxygroup=nobody
])
AC_SUBST(DGPROXYGROUP, "$proxygroup")

AC_MSG_CHECKING(for piddir)
AC_ARG_WITH(piddir,
[AC_HELP_STRING([--with-piddir@<:@=${localstatedir}/run@:>@], [path for pid file])],
[if test "x${withval}" != "x" ; then
  AC_MSG_RESULT(yes)
  piddir=${withval}
else
  AC_MSG_RESULT(no)
  piddir="${localstatedir}/run"
fi], [
  # disable by default
  AC_MSG_RESULT(no)
  piddir="${localstatedir}/run"
])
AC_FINALIZE_VAR(DGPIDDIR,"$piddir")
AC_SUBST(DGPIDDIR)


AC_MSG_CHECKING(for logdir)
AC_ARG_WITH(logdir,
[AC_HELP_STRING([--with-logdir@<:@=${localstatedir}/log/${PACKAGE_NAME}@:>@], [path for log files])],
[if test "x${withval}" != "x" ; then
  AC_MSG_RESULT(yes)
  logdir=${withval}
else
  AC_MSG_RESULT(no)
  logdir="${localstatedir}/log/${PACKAGE_NAME}"
fi], [
  # disable by default
  AC_MSG_RESULT(no)
  logdir="${localstatedir}/log/${PACKAGE_NAME}"
])
AC_FINALIZE_VAR(DGLOGLOCATION,"$logdir")
AC_SUBST(DGLOGLOCATION)

PKG_PROG_PKG_CONFIG

# asking user if they want PCRE support
AC_MSG_CHECKING(for PCRE support)
AC_ARG_ENABLE(
pcre,
[AC_HELP_STRING([--enable-pcre@<:@=yes@:>@], [Enable support for the PCRE library])],
[ if test "x$enableval" = "xno"; then
pcre=false
AC_MSG_RESULT(no)
else
pcre=true
AC_MSG_RESULT(yes)
fi
],
[ # enable by default
pcre=true
AC_MSG_RESULT(yes)
]
)
if test "x$pcre" = "xtrue"; then
PKG_CHECK_MODULES([PCRE],[libpcre >= 6.0])
AC_DEFINE([HAVE_PCRE],[],[Define to enable PCRE support])
PCRE_LIBS="-lpcreposix ${PCRE_LIBS}"
else
AC_CHECK_FUNCS([regcomp])
fi
AM_CONDITIONAL(HAVE_PCRE, test "x$pcre" = "xtrue")

# ask user if they want a backtrace logged after segfault
AC_MSG_CHECKING(for backtrace on segfault support)
AC_ARG_ENABLE(
segv_backtrace,
[AC_HELP_STRING([--enable-segv-backtrace@<:@=no@:>@], [Enable logging a backtrace when a segmentation fault occurs])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
else
# check for native header & func (no library)
AC_CHECK_FUNCS(backtrace, [AC_MSG_RESULT(native)], [
AC_MSG_RESULT(no)
# native not found, so look for linked
LIBS="-lexecinfo ${LIBS}"
AC_CHECK_LIB(execinfo, backtrace, [
AC_MSG_RESULT(linked)
], [
AC_MSG_RESULT(no)
AC_MSG_ERROR([no native or standard library backtrace function found! (needed by "--enable-segv-backtrace")])
])
])
AC_DEFINE([ENABLE_SEGV_BACKTRACE],[],[Define to enable backtrace on segmentation fault])
# add -rdynamic to compiler flags to force output of symbol tables
CXXFLAGS="-rdynamic ${CXXFLAGS}"
fi
],
[ # disable by default
AC_MSG_RESULT(no)
])

# ask user if they want large file support on 32 bit systems
AC_MSG_CHECKING([for large file support])
AC_ARG_ENABLE(
lfs,
[AC_HELP_STRING([--enable-lfs@<:@=yes@:>@], [Enable large file support on 32 bit systems])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
else
lfsflags=`getconf LFS_CFLAGS`
lfsld=`getconf LFS_LDFLAGS`
lfslib=`getconf LFS_LIBS`
CXXFLAGS="${CXXFLAGS} $lfsflags"
LDFLAGS="${LDFLAGS} $lfsld"
LIBS="${LIBS} $lfslib"
AC_MSG_RESULT(yes)
fi
],
[ # enable by default
lfsflags=`getconf LFS_CFLAGS`
lfsld=`getconf LFS_LDFLAGS`
lfslib=`getconf LFS_LIBS`
CXXFLAGS="${CXXFLAGS} $lfsflags"
LDFLAGS="${LDFLAGS} $lfsld"
LIBS="${LIBS} $lfslib"
AC_MSG_RESULT(yes)
])

# ask the user if they want support for retrieving original destination IPs
# when acting as a transparent proxy
AC_MSG_CHECKING([for original destination IP checking support])
AC_ARG_ENABLE(
orig-ip,
[AC_HELP_STRING([--enable-orig-ip@<:@=no@:>@], [Enable support for checking the client's original destination IP address against HTTP request details when deployed as a transparent proxy (US-CERT VU@%:@435052). Currently only works on Linux.])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
origip=false
ORIGIPSUPPORT="#!! Not compiled !! "
else
AC_MSG_RESULT(yes)
origip=true
AC_DEFINE([ENABLE_ORIG_IP],[],[Define to enable original destination IP checking])
ORIGIPSUPPORT=""
fi
],
[ # disable by default
AC_MSG_RESULT(no)
origip=false
ORIGIPSUPPORT="#!! Not compiled !! "
])
AC_SUBST(ORIGIPSUPPORT)

# determine whether or not "off_t" is simply a typedef of
# "int", "unsigned int", "long", etc. - if it is, the String
# class won't compile if its off_t constructor is defined,
# as that would represent a function redefinition.
AC_MSG_CHECKING([for type collision with off_t])
AC_COMPILE_IFELSE(
[
 AC_LANG_PROGRAM(
 [[#include <sys/types.h>]],[[
 struct Foo{
  void f(const int);
void f(const long);
void f(const long unsigned);
void f(const unsigned int);
void f(const off_t);
 };]])
],[
   AC_MSG_RESULT([no])
],[
   AC_MSG_RESULT([yes])
   AC_DEFINE([OFFT_COLLISION],[],[Define if type "off_t" is a typedef of another type for which String already has a constructor])
])

# by default, we do not need the content scanner list or config directories, nor the download manager list directory
cslists=false
csconfigs=false
dmlists=false

# asking user if they want clamd support
AC_MSG_CHECKING(for clamd support)
AC_ARG_ENABLE(
clamd,
[AC_HELP_STRING([--enable-clamd@<:@=no@:>@], [Enable support for the ClamD content scanner])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
clamd=false
CLAMDSUPPORT="!! Not compiled !! "
else
AC_MSG_RESULT(yes)
clamd=true
cslists=true
csconfigs=true
CLAMDSUPPORT=""
AC_DEFINE([ENABLE_CLAMD],[],[Define to enable ClamD content scanner])
fi],
[
AC_MSG_RESULT(no)
clamd=false
CLAMDSUPPORT="!! Not compiled !! "
]
)
AM_CONDITIONAL(ENABLE_CLAMD, test "x$clamd" = "xtrue")
AC_SUBST(CLAMDSUPPORT)

# asking user if they want avastd support
AC_MSG_CHECKING(for avastd support)
AC_ARG_ENABLE(
avastd,
[AC_HELP_STRING([--enable-avastd@<:@=no@:>@], [Enable support for the AvastD content scanner])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
avastd=false
AVASTDSUPPORT="!! Not compiled !! "
else
AC_MSG_RESULT(yes)
avastd=true
cslists=true
csconfigs=true
AVASTDSUPPORT=""
AC_DEFINE([ENABLE_AVASTD],[],[Define to enable AvastD content scanner])
fi],
[
AC_MSG_RESULT(no)
avastd=false
AVASTDSUPPORT="!! Not compiled !! "
]
)
AM_CONDITIONAL(ENABLE_AVASTD, test "x$avastd" = "xtrue")
AC_SUBST(AVASTDSUPPORT)

# asking user if they want icap support
AC_MSG_CHECKING(for icap support)
AC_ARG_ENABLE(
icap,
[AC_HELP_STRING([--enable-icap@<:@=no@:>@], [Enable support for ICAP AV server content scanner])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
icap=false
ICAPSUPPORT="!! Not compiled !! "
else
AC_MSG_RESULT(yes)
icap=true
cslists=true
csconfigs=true
AC_DEFINE([ENABLE_ICAP],[],[Define to enable ICAP content scanner])
ICAPSUPPORT=""
fi],
[
AC_MSG_RESULT(no)
icap=false
ICAPSUPPORT="!! Not compiled !! "
]
)
AM_CONDITIONAL(ENABLE_ICAP, test "x$icap" = "xtrue")
AC_SUBST(ICAPSUPPORT)

# asking user if they want kavd support
AC_MSG_CHECKING(for kavd support)
AC_ARG_ENABLE(
kavd,
[AC_HELP_STRING([--enable-kavd@<:@=no@:>@], [Enable support for the Kaspersky AV daemon content scanner])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
kavd=false
KAVDSUPPORT="!! Not compiled !! "
else
AC_MSG_RESULT(yes)
kavd=true
cslists=true
csconfigs=true
KAVDSUPPORT=""
AC_DEFINE([ENABLE_KAVD],[],[Define to enable KAVD content scanner])
fi],
[
AC_MSG_RESULT(no)
kavd=false
KAVDSUPPORT="!! Not compiled !! "
]
)
AM_CONDITIONAL(ENABLE_KAVD, test "x$kavd" = "xtrue")
AC_SUBST(KAVDSUPPORT)

# asking user if they want command-line content scanner support
AC_MSG_CHECKING(for command-line content scanner support)
AC_ARG_ENABLE(
commandline,
[AC_HELP_STRING([--enable-commandline@<:@=no@:>@], [Enable support for command-line content scanners])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
commandline=false
COMMANDLINESUPPORT="!! Not compiled !! "
else
AC_MSG_RESULT(yes)
commandline=true
cslists=true
csconfigs=true
COMMANDLINESUPPORT=""
AC_DEFINE([ENABLE_COMMANDLINE],[],[Define to enable command-line content scanner])
fi],
[
AC_MSG_RESULT(no)
commandline=false
COMMANDLINESUPPORT="!! Not compiled !! "
])
AM_CONDITIONAL(ENABLE_COMMANDLINE, test "x$commandline" = "xtrue")
AC_SUBST(COMMANDLINESUPPORT)

# install CS configs and lists if necessary
AM_CONDITIONAL(NEED_CSLISTS, test "x$cslists" = "xtrue")
AM_CONDITIONAL(NEED_CSCONFIGS, test "x$csconfigs" = "xtrue")

# asking user if they want fancy downloadmanager support
AC_MSG_CHECKING(for fancy download manager support)
AC_ARG_ENABLE(
fancydm,
[AC_HELP_STRING([--enable-fancydm@<:@=yes@:>@], [Enable support for the fancy download manager])],
[ if test "x$enableval" = "xno"; then
fancydm=false
FANCYSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
fancydm=true
dmlists=true
FANCYSUPPORT=""
AC_DEFINE([ENABLE_FANCYDM],[],[Define to enable fancy download manager])
fi],
[
fancydm=true
dmlists=true
FANCYSUPPORT=""
AC_MSG_RESULT(yes)
AC_DEFINE([ENABLE_FANCYDM],[],[Define to enable fancy download manager])
]
)
AM_CONDITIONAL(ENABLE_FANCYDM, test "x$fancydm" = "xtrue")
AC_SUBST(FANCYSUPPORT)

# asking user if they want total block list support
AC_MSG_CHECKING(for total block list support)
AC_ARG_ENABLE(
totblock,
[AC_HELP_STRING([--enable-totalblocklist@<:@=no@:>@], [Enable support for total block list])],
[ if test "x$enableval" = "xyes"; then
AC_MSG_RESULT(yes)
totblock=true
dmlists=true
TOTALBLOCKSUPPORT=""
AC_DEFINE([TOTAL_BLOCK_LIST],[],[Define to enable support for total block list])
else
totblock=false
TOTALBLOCKSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
fi],
[
totblock=false
TOTALBLOCKSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
]
)
AM_CONDITIONAL(TOTAL_BLOCK_LIST, test "x$totblock" = "xtrue")
AC_SUBST(TOTALBLOCKSUPPORT)

# asking user if they want local list support
AC_MSG_CHECKING(for local list support)
AC_ARG_ENABLE(
locallists,
[AC_HELP_STRING([--enable-locallists@<:@=no@:>@], [Enable support for local lists])],
[ if test "x$enableval" = "xyes"; then
AC_MSG_RESULT(yes)
locallists=true
LOCALLISTSUPPORT=""
AC_DEFINE([LOCAL_LISTS],[],[Define to enable support for local lists])
else
locallists=false
LOCALLISTSSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
fi],
[
locallists=false
LOCALLISTSSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
]
)
AM_CONDITIONAL(LOCAL_LISTS, test "x$locallists" = "xtrue")
AC_SUBST(LOCALLISTSSUPPORT)

# asking user if they want referer exception support
AC_MSG_CHECKING(for referer exception support)
AC_ARG_ENABLE(
refererexception,
[AC_HELP_STRING([--enable-refererexception@<:@=yes@:>@], [Enable support for referer exception ])],
[ if test "x$enableval" = "xno"; then
refererexception=false
REFEREREXCEPTSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
refererexception=true
REFEREREXCEPTSUPPORT=""
AC_DEFINE([REFEREREXCEPT],[],[Define to enable support for referer exceptions])
fi],
[
AC_MSG_RESULT(yes)
refererexception=true
REFEREREXCEPTSUPPORT=""
AC_DEFINE([REFEREREXCEPT],[],[Define to enable support for referer exceptions])
]
)
AM_CONDITIONAL(REFEREREXCEPT, test "x$refererexception" = "xtrue")
AC_SUBST(REFEREREXCEPTSUPPORT)

# asking user if they want regexp redirects support
AC_MSG_CHECKING(for regexp redirects support)
AC_ARG_ENABLE(
rxredirects,
[AC_HELP_STRING([--enable-rxredirects@<:@=yes@:>@], [Enable support for regexp redirects])],
[ if test "x$enableval" = "xno"; then
rxredirects=false
RXREDIRECTSSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
rxredirects=true
RXREDIRECTSSUPPORT=""
AC_DEFINE([RXREDIRECTS],[],[Define to enable support for regexp redirects])
fi],
[
AC_MSG_RESULT(yes)
rxredirects=true
RXREDIRECTSSUPPORT=""
AC_DEFINE([RXREDIRECTS],[],[Define to enable support for regexp redirects ])
]
)
AM_CONDITIONAL(RXREDIRECTS, test "x$rxredirects" = "xtrue")
AC_SUBST(RXREDIRECTSSUPPORT)

# asking user if they want add header support
AC_MSG_CHECKING(for add header support)
AC_ARG_ENABLE(
addheader,
[AC_HELP_STRING([--enable-addheader@<:@=yes@:>@], [Enable support for add header])],
[ if test "x$enableval" = "xno"; then
addheader=false
ADDHEADERSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
addheader=true
ADDHEADERSUPPORT=""
AC_DEFINE([ADDHEADER],[],[Define to enable support for add header])
fi],
[
AC_MSG_RESULT(yes)
addheader=true
ADDHEADERSUPPORT=""
AC_DEFINE([ADDHEADER],[],[Define to enable support for add header ])
]
)
AM_CONDITIONAL(ADDHEADER, test "x$addheader" = "xtrue")
AC_SUBST(ADDHEADERSUPPORT)

# asking user if they want ssl extra lists support
AC_MSG_CHECKING(for ssl extra lists support)
AC_ARG_ENABLE(
sslextralists,
[AC_HELP_STRING([--enable-sslextralists@<:@=yes@:>@], [Enable support for ssl extra lists])],
[ if test "x$enableval" = "xno"; then
sslextralists=false
SSL_EXTRA_LISTSSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
sslextralists=true
SSL_EXTRA_LISTSSUPPORT=""
AC_DEFINE([SSL_EXTRA_LISTS],[],[Define to enable support for ssl extra lists])
fi],
[
AC_MSG_RESULT(yes)
sslextralists=true
SSL_EXTRA_LISTSSUPPORT=""
AC_DEFINE([SSL_EXTRA_LISTS],[],[Define to enable support for ssl extra lists ])
]
)
AM_CONDITIONAL(SSL_EXTRA_LISTS, test "x$sslextralists" = "xtrue")
AC_SUBST(SSL_EXTRA_LISTSSUPPORT)

# asking user if they want searchwords support
AC_MSG_CHECKING(for searchwords support)
AC_ARG_ENABLE(
searchwords,
[AC_HELP_STRING([--enable-searchwords@<:@=yes@:>@], [Enable support for ssl extra lists])],
[ if test "x$enableval" = "xno"; then
searchwords=false
SEARCHWORDSSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
searchwords=true
SEARCHWORDSSUPPORT=""
AC_DEFINE([SEARCHWORDS],[],[Define to enable support for ssl extra lists])
fi],
[
AC_MSG_RESULT(yes)
searchwords=true
SEARCHWORDSSUPPORT=""
AC_DEFINE([SEARCHWORDS],[],[Define to enable support for ssl extra lists ])
]
)
AM_CONDITIONAL(SEARCHWORDS, test "x$searchwords" = "xtrue")
AC_SUBST(SEARCHWORDSSUPPORT)

# asking user if they want legacy log support
AC_MSG_CHECKING(for legacy log support)
AC_ARG_ENABLE(
legacylog,
[AC_HELP_STRING([--enable-legacylog@<:@=yes@:>@], [Enable support for legacy log format])],
[ if test "x$enableval" = "xno"; then
legacylog=false
LEGACY_LOGSUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
legacylog=true
LEGACY_LOGSUPPORT=""
AC_DEFINE([LEGACY_LOG],[],[Define to enable support for legacy log format])
fi],
[
AC_MSG_RESULT(yes)
legacylog=true
LEGACY_LOGSUPPORT=""
AC_DEFINE([LEGACY_LOG],[],[Define to enable support for legacy log format ])
]
)
AM_CONDITIONAL(LEGACY_LOG, test "x$legacylog" = "xtrue")
AC_SUBST(LEGACY_LOGSUPPORT)

# asking user if they want trickle downloadmanager support
AC_MSG_CHECKING(for trickle download manager support)
AC_ARG_ENABLE(
trickledm,
[AC_HELP_STRING([--enable-trickledm@<:@=no@:>@], [Enable support for the trickle download manager])],
[ if test "x$enableval" = "xno"; then
trickledm=false
TRICKLESUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
else
AC_MSG_RESULT(yes)
trickledm=true
dmlists=true
TRICKLESUPPORT=""
AC_DEFINE([ENABLE_TRICKLEDM],[],[Define to enable trickle download manager])
fi],
[
trickledm=false
TRICKLESUPPORT="#!! Not compiled !! "
AC_MSG_RESULT(no)
]
)
AM_CONDITIONAL(ENABLE_TRICKLEDM, test "x$trickledm" = "xtrue")
AC_SUBST(TRICKLESUPPORT)

# install DM lists if necessary
AM_CONDITIONAL(NEED_DMLISTS, test "x$dmlists" = "xtrue")

# asking user if they want NTLM auth support
AC_MSG_CHECKING(for NTLM support)
AC_ARG_ENABLE(
ntlm,
[AC_HELP_STRING([--enable-ntlm@<:@=no@:>@], [Enable support for the NTLM auth plugin])],
[ if test "x$enableval" = "xno"; then
AC_MSG_RESULT(no)
ntlm=false
NTLMSUPPORT="!! Not compiled !! "
else
AC_MSG_RESULT(yes)
ntlm=true
NTLMSUPPORT=""
AC_DEFINE([ENABLE_NTLM],[],[Define to enable NTLM auth plugin])
# now need to check if they're using an iconv library, rather
# than a native iconv implementation
AC_ARG_WITH(libiconv,
[AC_HELP_STRING([--with-libiconv@<:@=NONE@:>@], [Specify search path on a system which requires an external iconv library (only used in conjunction with NTLM auth plugin).])],
[ # check for header & func (in library) in given prefix
if test "x$withval" != "x"; then
CPPFLAGS="${CPPFLAGS} -I${withval}/include"
LIBS="-L${withval}/lib -liconv ${LIBS}"
else
LIBS="-liconv ${LIBS}"
fi
AC_CHECK_LIB(iconv, iconv, [AC_MSG_RESULT(linked)], [
AC_MSG_RESULT(no)
AC_CHECK_LIB(iconv, libiconv, [AC_MSG_RESULT(linked)], [
AC_MSG_ERROR([no libiconv found in given search path! (needed by NTLM plugin)])
])
])
],
[ # check for native header & func (no library)
AC_CHECK_FUNCS(iconv, [AC_MSG_RESULT(native)], [
AC_MSG_RESULT(no)
# native not found, so look for linked
LIBS="-liconv ${LIBS}"
AC_CHECK_LIB(iconv, iconv, [
AC_MSG_RESULT(linked)
], [
AC_MSG_RESULT(no)
AC_CHECK_LIB(iconv, libiconv, [AC_MSG_RESULT(linked)], [
AC_MSG_ERROR([no native or standard library iconv function found! (needed by NTLM plugin - try again with "--with-libiconv"?)])
])
])
])
]
)
fi],
[
AC_MSG_RESULT(no)
ntlm=false
NTLMSUPPORT="!! Not compiled !! "
]
)
AM_CONDITIONAL(ENABLE_NTLM, test "x$ntlm" = "xtrue")
AC_SUBST(NTLMSUPPORT)

# asking user if they want DNS auth support
AC_MSG_CHECKING(for DNS support)
AC_ARG_ENABLE(
dnsauth,
[AC_HELP_STRING([--enable-dnsauth@<:@=no@:>@], [Enable support for the DNS auth plugin])],
[ if test "x$enableval" = "xno"; then
	AC_MSG_RESULT(no)
	dnsauth=false
	DNSAUTHSUPPORT="!! Not compiled !! "
else
	AC_MSG_RESULT(yes)
	dnsauth=true
	DNSAUTHSUPPORT=""
	AC_DEFINE([PRT_DNSAUTH],[],[Define to enable DNS auth plugin])
fi],
[
	AC_MSG_RESULT(no)
	dnsauth=false
	DNSAUTHSUPPORT="!! Not compiled !! "
]
)
AM_CONDITIONAL(PRT_DNSAUTH, test "x$dnsauth" = "xtrue")
AC_SUBST(DNSAUTHSUPPORT)


AC_ARG_WITH(filedescriptors,
  AS_HELP_STRING([--with-filedescriptors=NUMBER],
                 [Force support of NUMBER filedescriptors]),
[
  case ${withval} in
    [[0-9]]*)
      dans_filedescriptors_num=$withval
      ;;
    *)
      AC_MSG_ERROR(--with-filedescriptors expects a numeric argument)
      ;;
    esac
])

if test "$dans_filedescriptors_num" -lt 512; then
    AC_MSG_WARN([$dans_filedescriptors_num may not be enough filedescriptors if])
    AC_MSG_WARN([e2guardian will be very busy.])
    AC_DEFINE_UNQUOTED(DANS_MAXFD, $dans_filedescriptors_num,[Maximum number of open filedescriptors])
fi

if test "$dans_filedescriptors_num" -ge 512; then
    AC_DEFINE_UNQUOTED(DANS_MAXFD, $dans_filedescriptors_num,[Maximum number of open filedescriptors])
fi

# asking the user if they want email notifications
AC_MSG_CHECKING(for email notification support)
AC_ARG_ENABLE(
email,
[AC_HELP_STRING([--enable-email@<:@=no@:>@], [Enable support for email reporting functionality])],
[ if test "x$enableval" = "xyes"; then
email=true
EMAILSUPPORT=""
AC_MSG_RESULT(yes)
AC_DEFINE([ENABLE_EMAIL],[],[Define to enable email reporting])
else
email=false
EMAILSUPPORT="#!! Not compiled !!"
AC_MSG_RESULT(no)
fi],
[
email=false
EMAILSUPPORT="#!! Not compiled !!"
AC_MSG_RESULT(no)
])
AC_SUBST(EMAILSUPPORT)

AC_DEFINE_UNQUOTED([DG_CONFIGURE_OPTIONS], ["$ac_configure_args"], [Record configure-time options])

libdir="${libdir}/${PACKAGE_NAME}"

AC_ARG_WITH(sysconfsubdir,
[AC_HELP_STRING([--with-sysconfsubdir@<:@=e2guardian@:>@], [subdirectory under sysconfdir in which to place config files])],
[if test "x$withval" != "x"; then
dgsysconfdir="${sysconfdir}/${withval}"
else
dgsysconfdir="${sysconfdir}"
fi],
[dgsysconfdir="${sysconfdir}/${PACKAGE_NAME}"])

AC_FINALIZE_VAR(DGLIBDIR,"${libdir}")
AC_SUBST(DGLIBDIR)
AC_FINALIZE_VAR(DGBINDIR,"${sbindir}")
AC_SUBST(DGBINDIR)
AC_FINALIZE_VAR(DGCONFDIR,"${dgsysconfdir}")
AC_SUBST(DGCONFDIR)
AC_FINALIZE_VAR(DGDATADIR,"${datadir}/${PACKAGE_NAME}")
AC_SUBST(DGDATADIR)
AC_FINALIZE_VAR(DGCONFFILE,"${dgsysconfdir}/${PACKAGE_NAME}.conf")
AC_SUBST(DGCONFFILE)

AC_CONFIG_FILES([Makefile
data/Makefile
data/languages/Makefile
data/scripts/Makefile
data/scripts/bsd-init
data/scripts/e2guardian
data/scripts/logrotation
data/scripts/solaris-init
data/scripts/systemv-init
migration_installation/installation_or_migration_from_dg.sh
migration_installation/Makefile
doc/Makefile
configs/e2guardian.conf
configs/e2guardianf1.conf
configs/Makefile
configs/lists/Makefile
configs/lists/phraselists/Makefile
configs/lists/blacklists/Makefile
configs/lists/bannedrooms/Makefile
configs/lists/contentscanners/Makefile
configs/lists/weightedphraselist
configs/lists/exceptionphraselist
configs/lists/bannedphraselist
configs/lists/bannedurllist
configs/lists/bannedsitelist
configs/downloadmanagers/Makefile
configs/downloadmanagers/default.conf
configs/downloadmanagers/fancy.conf
configs/downloadmanagers/trickle.conf
configs/contentscanners/Makefile
configs/contentscanners/clamdscan.conf
configs/contentscanners/avastdscan.conf
configs/contentscanners/icapscan.conf
configs/contentscanners/kavdscan.conf
configs/contentscanners/commandlinescan.conf
configs/authplugins/Makefile
configs/authplugins/ip.conf
configs/lists/authplugins/Makefile
configs/lists/downloadmanagers/Makefile
                src/Makefile
])

AC_OUTPUT
