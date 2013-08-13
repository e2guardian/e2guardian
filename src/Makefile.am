clean_SUBDIRS= . downloadmanagers contentscanners authplugins

# A MASSIVE thank you to Lawrence Manning for pointing out the
# -export-dynamic option was needed to solve a long problem
# which stopped DG2.9 from actually running ever.
# Daniel Barron Fri 18th March 2005

# Unfortunately, since it was never made to work on anything
# other than Linux, libtool support has been removed in favour
# of configure-time options (at DB's request).

if ENABLE_CLAMD
CLAMDSCAN_SOURCE = contentscanners/clamdscan.cpp
else
CLAMDSCAN_SOURCE =
endif

if ENABLE_AVASTD
AVASTDSCAN_SOURCE = contentscanners/avastdscan.cpp
else
AVASTDSCAN_SOURCE =
endif

if ENABLE_ICAP
ICAPSCAN_SOURCE = contentscanners/icapscan.cpp
else
ICAPSCAN_SOURCE =
endif

if ENABLE_KAVD
KAVDSCAN_SOURCE = contentscanners/kavdscan.cpp
else
KAVDSCAN_SOURCE =
endif

if ENABLE_COMMANDLINE
COMMANDLINE_SOURCE = contentscanners/commandlinescan.cpp
else
COMMANDLINE_SOURCE =
endif

DEFAULTDM_SOURCE = downloadmanagers/default.cpp

if ENABLE_FANCYDM
FANCYDM_SOURCE = downloadmanagers/fancy.cpp
else
FANCYDM_SOURCE =
endif

if ENABLE_TRICKLEDM
TRICKLEDM_SOURCE = downloadmanagers/trickle.cpp
else
TRICKLEDM_SOURCE =
endif

PROXYAUTH_SOURCE = authplugins/proxy.cpp
IDENTAUTH_SOURCE = authplugins/ident.cpp
IPAUTH_SOURCE = authplugins/ip.cpp
DIGESTAUTH_SOURCE = authplugins/digest.cpp

if ENABLE_NTLM
NTLMAUTH_SOURCE = authplugins/ntlm.cpp
else
NTLMAUTH_SOURCE =
endif

sbin_PROGRAMS = dansguardian 

dansguardian_CXXFLAGS = $(PCRE_CFLAGS) $(AM_CXXFLAGS)
dansguardian_LDADD = $(PCRE_LIBS) $(AM_LIBS)
dansguardian_CPPFLAGS = -D__CONFFILE='"$(DGCONFFILE)"' \
			-D__LOGLOCATION='"$(DGLOGLOCATION)/"' \
			-D__PIDDIR='"$(DGPIDDIR)"' \
			-D__PROXYUSER='"$(DGPROXYUSER)"' \
			-D__PROXYGROUP='"$(DGPROXYGROUP)"' \
			-D__CONFDIR='"$(DGCONFDIR)"' \
			$(AM_CPPFLAGS)
dansguardian_SOURCES = String.cpp String.hpp \
                       FDTunnel.cpp FDTunnel.hpp \
                       ConnectionHandler.cpp ConnectionHandler.hpp \
                       DataBuffer.cpp DataBuffer.hpp \
                       HTTPHeader.cpp HTTPHeader.hpp \
                       NaughtyFilter.cpp NaughtyFilter.hpp \
		       BackedStore.cpp BackedStore.hpp\
                       RegExp.cpp RegExp.hpp \
		       FDFuncs.cpp FDFuncs.hpp \
		       BaseSocket.cpp BaseSocket.hpp \
                       Socket.cpp Socket.hpp \
                       FatController.cpp FatController.hpp \
                       UDSocket.cpp UDSocket.hpp \
                       SysV.cpp SysV.hpp \
                       ListContainer.cpp ListContainer.hpp \
                       Auth.cpp Auth.hpp \
                       HTMLTemplate.cpp HTMLTemplate.hpp \
                       LanguageContainer.cpp LanguageContainer.hpp \
                       DynamicURLList.cpp DynamicURLList.hpp \
		       DynamicIPList.cpp DynamicIPList.hpp \
                       ImageContainer.cpp ImageContainer.hpp \
		       IPList.cpp IPList.hpp \
                       OptionContainer.cpp OptionContainer.hpp \
                       FOptionContainer.cpp FOptionContainer.hpp \
                       ListManager.cpp ListManager.hpp \
                       md5.cpp md5.hpp \
                       DownloadManager.cpp DownloadManager.hpp \
                       ConfigVar.cpp ConfigVar.hpp \
                       ContentScanner.cpp ContentScanner.hpp \
		       SocketArray.cpp SocketArray.hpp \
                       dansguardian.cpp \
		       Plugin.hpp \
                       CertificateAuthority.cpp CertificateAuthority.hpp \
		       $(ICAPSCAN_SOURCE) \
		       $(KAVDSCAN_SOURCE) $(CLAMDSCAN_SOURCE) \
		       $(AVASTDSCAN_SOURCE) \
		       $(COMMANDLINE_SOURCE) \
		       $(DEFAULTDM_SOURCE) $(FANCYDM_SOURCE) \
		       $(TRICKLEDM_SOURCE) $(PROXYAUTH_SOURCE) \
		       $(IDENTAUTH_SOURCE) $(IPAUTH_SOURCE) \
		       $(NTLMAUTH_SOURCE) $(DIGESTAUTH_SOURCE)
