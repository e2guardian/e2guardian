DISTCLEANFILES = Makefile.in 

E2DATADIR = $(E2CONFDIR)/lists/common

SUBDIRS = . 

WLISTS = authexceptioniplist \
authexceptionsitelist \
authexceptionurllist \
bannedclientlist \
bannediplist \
browserregexplist \
embededreferersiteiplist \
embededreferersitelist \
embededrefererurllist \
exceptionclientlist \
exceptioniplist \
nologextensionlist \
nologregexpurllist \
nologsiteiplist \
nologsitelist \
nologurllist \
nomitmsiteiplist \
nomitmsitelist \
searchregexplist \
searchexceptionregexplist \
README
 
EXTRA_DIST = 

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
