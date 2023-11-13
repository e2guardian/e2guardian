clean_SUBDIRS= . downloadmanagers contentscanners authplugins
DISTCLEANFILES = Makefile.in


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
#FANCYDM_SOURCE = d$downloadmanagers/fancy.cpp
FANCYDM_SOURCE = 
TRICKLEDM_SOURCE = downloadmanagers/trickle.cpp

IDENTAUTH_SOURCE = authplugins/ident.cpp
IPAUTH_SOURCE = authplugins/ip.cpp
PORTAUTH_SOURCE = authplugins/port.cpp
HEADERAUTH_SOURCE = authplugins/header.cpp
PFBASICAUTH_SOURCE = authplugins/ProxyFirstBasic.cpp
BEARERBASICAUTH_SOURCE = authplugins/BearerBasic.cpp

NTLMAUTH_SOURCE =

if PRT_DNSAUTH
DNSAUTH_SOURCE = authplugins/dnsauth.cpp
else
DNSAUTH_SOURCE =
endif


sbin_PROGRAMS = e2guardian

e2guardian_CXXFLAGS = $(PCRE_CFLAGS) $(AM_CXXFLAGS) -Wall
e2guardian_LDADD = $(PCRE_LIBS) $(AM_LIBS)
e2guardian_CPPFLAGS = -D__CONFFILE='"$(E2CONFFILE)"' \
			-D__LOGLOCATION='"$(E2LOGLOCATION)/"' \
			-D__PIDDIR='"$(E2PIDDIR)"' \
			-D__PROXYUSER='"$(E2PROXYUSER)"' \
			-D__PROXYGROUP='"$(E2PROXYGROUP)"' \
			-D__CONFDIR='"$(E2CONFDIR)"' \
			$(AM_CPPFLAGS)
e2guardian_SOURCES = String.cpp String.hpp \
                       FDTunnel.cpp FDTunnel.hpp \
                       ConnectionHandler.cpp ConnectionHandler.hpp \
                       DataBuffer.cpp DataBuffer.hpp \
                       HTTPHeader.cpp HTTPHeader.hpp \
                       ICAPHeader.cpp ICAPHeader.hpp \
                       NaughtyFilter.cpp NaughtyFilter.hpp \
		       BackedStore.cpp BackedStore.hpp\
                       RegExp.cpp RegExp.hpp \
		       BaseSocket.cpp BaseSocket.hpp \
                       Socket.cpp Socket.hpp \
                       UdpSocket.cpp UdpSocket.hpp \
                       FatController.cpp FatController.hpp \
                       UDSocket.cpp UDSocket.hpp \
                       SysV.cpp SysV.hpp \
                       ListContainer.cpp ListContainer.hpp \
                       ListMeta.cpp ListMeta.hpp \
                       StoryBoard.cpp StoryBoard.hpp \
                       SBFunction.cpp SBFunction.hpp \
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
                       ConfigReader.cpp ConfigReader.hpp \
                       ContentScanner.cpp ContentScanner.hpp \
		       SocketArray.cpp SocketArray.hpp \
                       e2guardian.cpp \ Plugin.hpp \
		       LOptionContainer.cpp LOptionContainer.hpp \
                       CertificateAuthority.cpp CertificateAuthority.hpp \
		       Queue.hpp, UrlRec.hpp, \
                       Logger.hpp Logger.cpp \
                       LoggerConfigurator.hpp LoggerConfigurator.cpp \
			LogFormat.hpp LogFormat.cpp \
			LogTransfer.hpp LogTransfer.cpp \
		       Auth.cpp Auth.hpp \
           Utils/Path.hpp, Utils/Path.cpp \
           \
		       $(ICAPSCAN_SOURCE) \
           $(KAVDSCAN_SOURCE) $(CLAMDSCAN_SOURCE) \
           $(AVASTDSCAN_SOURCE) \
           $(COMMANDLINE_SOURCE) \
           $(DEFAULTDM_SOURCE) $(FANCYDM_SOURCE) \
           $(TRICKLEDM_SOURCE)  \
           $(IDENTAUTH_SOURCE) $(IPAUTH_SOURCE) \
           $(DNSAUTH_SOURCE) $(PORTAUTH_SOURCE) \
		       $(BEARERBASICAUTH_SOURCE) \
		       $(HEADERAUTH_SOURCE) $(PFBASICAUTH_SOURCE)
