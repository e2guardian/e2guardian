DISTCLEANFILES = Makefile.in \
		bannedphraselist bannedsitelist bannedurllist \
		exceptionphraselist weightedphraselist \
		oldbannedphraselist \
		oldexceptionphraselist oldweightedphraselist

E2DATADIR = $(E2CONFDIR)/lists/example.group

SUBDIRS = . 

WLISTS = addheaderregexplist \
bannedsearchoveridelist \
bannedextensionlist \
bannediplist \
bannedmimetypelist \
bannedphraselist \
oldbannedphraselist \
bannedregexpheaderlist \
bannedregexpurllist \
bannedregexpuseragentlist \
bannedsearchlist \
bannedsiteiplist \
bannedtimelist \
exceptionvirussiteiplist \
bannedsitelist \
bannedsslsiteiplist \
bannedsslsitelist \
bannedurllist \
blankettimelist \
contentregexplist \
exceptionextensionlist \
exceptionvirusextensionlist \
exceptionfilesiteiplist \
exceptionfilesitelist \
exceptionfileurllist \
exceptionclientlist \
exceptionmimetypelist \
exceptionphraselist \
oldexceptionphraselist \
exceptionregexpurllist \
exceptionregexpuseragentlist \
exceptionsiteiplist \
exceptionsitelist \
exceptionregexpheaderlist \
exceptionurllist \
greysiteiplist \
greysitelist \
greysslsiteiplist \
greysslsitelist \
greyurllist \
headerregexplist \
localbannedsearchlist \
localbannedsiteiplist \
localbannedsitelist \
localbannedsslsiteiplist \
localbannedsslsitelist \
localbannedurllist \
localexceptionsiteiplist \
localexceptionsitelist \
localexceptionurllist \
localgreysiteiplist \
localgreysitelist \
localgreysslsiteiplist \
localgreysslsitelist \
localgreyurllist \
logregexpurllist \
logsiteiplist \
logsitelist \
logurllist \
nocheckcertsiteiplist \
nocheckcertsitelist \
refererexceptionsiteiplist \
refererexceptionsitelist \
refererexceptionurllist \
responseheaderregexplist \
sslsiteregexplist \
urlredirectregexplist \
urlregexplist \
ipnobypass \
domainsnobypass \
urlnobypass \
weightedphraselist \
oldweightedphraselist \
README
 
EXTRA_DIST = bannedphraselist.in \
oldbannedphraselist.in \
bannedsitelist.in \
bannedurllist.in \
exceptionphraselist.in \
oldexceptionphraselist.in \
domainsnobypass.in \
urlnobypass.in \
weightedphraselist.in \
oldweightedphraselist.in

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
		for l in $(WLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
	done


uninstall-local:
	for l in $(WLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
	done
