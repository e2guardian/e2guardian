# Autoconf script


AC_DEFINE([__SSLMITM],[""],[Define to enable SSL MITM])
AC_DEFINE([FD_SETSIZE_OVERIDE],[""],[Define to allow DANS_MAXFD to exceed FD_SETSIZE])

AC_PREREQ(2.57)
AC_INIT(e2guardian, 5.3.5)
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([dgconfig.h])
AC_CONFIG_MACRO_DIR([m4])

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

#########################################################################
# Get GCC version
#########################################################################
GCC_VERSION=$(gcc --version | head -1 | awk '{print $NF}')

GCC_VERSION_MAJOR=$(echo $GCC_VERSION |cut -d'.' -f1 2>/dev/null)
GCC_VERSION_MINOR=$(echo $GCC_VERSION |cut -d'.' -f2 2>/dev/null)
GCC_VERSION_PATCH=$(echo $GCC_VERSION |cut -d'.' -f3 2>/dev/null)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netdb.h netinet/in.h stdlib.h])
AC_CHECK_HEADERS([string.h sys/socket.h sys/time.h syslog.h unistd.h locale.h])
AC_CHECK_HEADERS([sys/types.h sys/un.h sys/poll.h sys/epoll.h sys/resource.h])
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
[if test "x${withval}" = "xoff" ; then
  AC_MSG_RESULT(no)
else
  AC_MSG_RESULT(yes)
  dgdebug=${withval}
  AC_DEFINE(DGDEBUG, 1, [Define to enable debug build mode])
fi], [
  # disable by default
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING(for newdebug option)
AC_ARG_WITH(newdebug,
[AC_HELP_STRING([--with-newdebug@<:@=off@:>@], [switch off debuglevel build mode])],
[if test "x${withval}" = "xon" ; then
  AC_MSG_RESULT(YES)
  AC_DEFINE(NEWDEBUG_ON, 1, [Define to enable debuglevel build mode])
else
  AC_MSG_RESULT(no)
# enable by default
  newdebug=${withval}
  AC_DEFINE(NEWDEBUG_OFF, 1, [Define to disable debuglevel build mode])
fi], [
  # enable by default
  AC_DEFINE(NEWDEBUG_ON, 1, [Define to enable debuglevel build mode])
  AC_MSG_RESULT(yes)
])

AC_MSG_CHECKING(for netdebug option)
AC_ARG_WITH(netdebug,
[AC_HELP_STRING([--with-netdebug@<:@=off@:>@], [switch on netdebug build mode])],
[if test "x${withval}" = "xoff" ; then
  AC_MSG_RESULT(no)
else
  AC_MSG_RESULT(yes)
  netdebug=${withval}
  AC_DEFINE(NETDEBUG, 1, [Define to enable debug build mode for socket functions])
fi], [
  # disable by default
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING(for REdebug option)
AC_ARG_WITH(redebug,
[AC_HELP_STRING([--with-redebug@<:@=off@:>@], [switch on redebug build mode])],
[if test "x${withval}" = "xoff" ; then
  AC_MSG_RESULT(no)
else
  AC_MSG_RESULT(yes)
  redebug=${withval}
  AC_DEFINE(REDEBUG, 1, [Define to enable debug build mode for regexp functions])
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

AC_CHECK_HEADERS([pthread.h], [ LIBS="-lpthread ${LIBS}"], [
echo "pthread.h required, failing"
exit -1
])
#AC_CHECK_HEADERS([event2/thread.h], [
#LIBS="-levent_pthreads ${LIBS}"
#], [
#echo "libevent_pthreads required, failing"
#exit -1
#])

[if test "$GCC_VERSION_MAJOR" -eq 4; then
	if test "$GCC_VERSION_MINOR" -ge 9; then
		if test "$GCC_VERSION_PATCH" -ge 3; then
                        echo "Version: $GCC_VERSION"
                        CXXFLAGS="${CXXFLAGS} --std=c++11"
                fi
        fi
	echo "Version: $GCC_VERSION "
        CXXFLAGS="${CXXFLAGS} --std=c++1y"
else
        if test "$GCC_VERSION_MAJOR" -ge 5; then
        echo "Version: $GCC_VERSION "
        CXXFLAGS="${CXXFLAGS} --std=c++11"
	else
	echo "Version: $GCC_VERSION "
        CXXFLAGS="${CXXFLAGS} --std=c++1y"
	fi
fi
]

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
CXXFLAGS="${CXXFLAGS} $lfsflags -DFD_SETSIZE=65535"
LDFLAGS="${LDFLAGS} $lfsld"
LIBS="${LIBS} $lfslib"
AC_MSG_RESULT(yes)
fi
],
[ # enable by default
lfsflags=`getconf LFS_CFLAGS`
lfsld=`getconf LFS_LDFLAGS`
lfslib=`getconf LFS_LIBS`
CXXFLAGS="${CXXFLAGS} $lfsflags -DFD_SETSIZE=65535"
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

# asking user if they want SSL MITM support
AC_MSG_CHECKING(for SSL MITM support)
AC_ARG_ENABLE(
sslmitm,
[AC_HELP_STRING([--enable-sslmitm@<:@=no@:>@], [Enable support for the SSL MITM plugin])],
[ if test "x$enableval" = "xno"; then
	AC_MSG_RESULT(no)
	sslmitm=false
	SSLMITMSUPPORT="!! Not compiled !! "
else
	AC_MSG_RESULT(yes)
	sslmitm=true
	SSLMITMSUPPORT=""
	LIBS="${LIBS} -lssl -lcrypto"
	AC_DEFINE([__SSLMITM],[],[Define to enable SSL MITM ])
	AC_DEFINE([__SSLCERT],[],[Define to enable SSL CERT ])
	PKG_CHECK_MODULES([OPENSSL],[ openssl >= 1.0.1])
fi],
[
	AC_MSG_RESULT(no)
	sslmitm=false
	SSLMITMSUPPORT="!! Not compiled !! "
]
)
AM_CONDITIONAL(__SSLMITM, test "x$sslmitm" = "xtrue")
AM_CONDITIONAL(__SSLCERT, test "x$sslmitm" = "xtrue")
AC_SUBST(SSLMITMSUPPORT)

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
	LIBS="${LIBS} -lresolv"
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
data/scripts/e2guardian.service
data/scripts/e2guardianrasp.service
doc/Makefile
configs/e2guardian.conf
configs/e2guardianf1.conf
configs/examplef1.story
configs/Makefile
configs/lists/Makefile
configs/lists/phraselists/Makefile
configs/lists/newphraselists/Makefile
configs/lists/bannedrooms/Makefile
configs/lists/contentscanners/Makefile
configs/lists/bannedphraselist
configs/lists/newbannedphraselist
configs/lists/bannedurllist
configs/lists/bannedsitelist
configs/lists/domainsnobypass
configs/lists/urlnobypass
configs/lists/exceptionphraselist
configs/lists/newexceptionphraselist
configs/lists/weightedphraselist
configs/lists/newweightedphraselist
configs/downloadmanagers/Makefile
configs/downloadmanagers/default.conf
configs/contentscanners/Makefile
configs/contentscanners/clamdscan.conf
configs/contentscanners/avastdscan.conf
configs/contentscanners/icapscan.conf
configs/contentscanners/kavdscan.conf
configs/contentscanners/commandlinescan.conf
configs/authplugins/Makefile
configs/authplugins/ip.conf
configs/authplugins/port.conf
configs/lists/authplugins/Makefile
configs/lists/downloadmanagers/Makefile
src/Makefile
])

AC_OUTPUT
