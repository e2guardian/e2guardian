DISTCLEANFILES = Makefile.in \
		bannedphraselist bannedsitelist bannedurllist \
		exceptionphraselist nocheckcertsitelist weightedphraselist

DGDATADIR = $(DGCONFDIR)/lists

SUBDIRS = phraselists . authplugins bannedrooms

if NEED_CSLISTS
SUBDIRS += contentscanners
endif
if NEED_DMLISTS
SUBDIRS += downloadmanagers
endif

WLISTS = nocheckcertsitelist bannedextensionlist bannediplist bannedmimetypelist \
	 bannedregexpurllist bannedsitelist \
	 bannedsearchlist bannedsslsitelist bannedurllist \
	 contentregexplist exceptioniplist exceptionsitelist \
	 exceptionurllist filtergroupslist greysitelist \
	 greyurllist pics bannedphraselist weightedphraselist \
	 exceptionphraselist bannediplist exceptioniplist urlregexplist \
	 exceptionregexpurllist exceptionextensionlist exceptionmimetypelist \
	 exceptionfilesitelist bannedregexpheaderlist headerregexplist \
	 exceptionfileurllist logsitelist logurllist logregexpurllist \
	 addheaderregexplist greysslsitelist \
	 localbannedsearchlist localbannedsitelist localbannedsslsitelist \
	 localbannedurllist localexceptionsitelist localexceptionurllist \
	 localgreysitelist localgreysslsitelist localgreyurllist \
	 refererexceptionsitelist refererexceptionurllist searchregexplist \
	 embededreferersitelist embededrefererurllist \
	 authexceptionsitelist authexceptionurllist bannedsitelistwithbypass \
	 urlredirectregexplist sslsiteregexplist
 
EXTRA_DIST = nocheckcertsitelist bannedextensionlist bannediplist bannedmimetypelist \
	 bannedregexpurllist bannedsitelist.in bannedurllist.in \
	 contentregexplist exceptioniplist exceptionsitelist \
	 exceptionurllist filtergroupslist greysitelist \
	 greyurllist pics bannedphraselist.in weightedphraselist.in \
	 exceptionphraselist.in bannediplist exceptioniplist urlregexplist \
	 exceptionregexpurllist exceptionextensionlist exceptionmimetypelist \
	 exceptionfilesitelist bannedregexpheaderlist headerregexplist \
	 exceptionfileurllist logsitelist logurllist logregexpurllist sslsiteregexplist

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(DGDATADIR) && \
		for l in $(WLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DGDATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(DGDATADIR)/$$l; \
	done


uninstall-local:
	for l in $(WLISTS) ; do \
		rm -f $(DESTDIR)$(DGDATADIR)/$$l ; \
	done
