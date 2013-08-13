MAINTAINERCLEANFILES = Makefile.in \
		       weightedphraselist bannedphraselist exceptionphraselist \
		       bannedsitelist bannedurllist

DGDATADIR = $(DGCONFDIR)/lists

SUBDIRS = phraselists . blacklists authplugins bannedrooms

if NEED_CSLISTS
SUBDIRS += contentscanners
endif
if NEED_DMLISTS
SUBDIRS += downloadmanagers
endif

WLISTS = bannedextensionlist bannediplist bannedmimetypelist \
	 bannedregexpurllist bannedsitelist bannedurllist \
	 contentregexplist exceptioniplist exceptionsitelist \
	 exceptionurllist filtergroupslist greysitelist \
	 greyurllist pics bannedphraselist weightedphraselist \
	 exceptionphraselist bannediplist exceptioniplist urlregexplist \
	 exceptionregexpurllist exceptionextensionlist exceptionmimetypelist \
	 exceptionfilesitelist bannedregexpheaderlist headerregexplist \
	 exceptionfileurllist logsitelist logurllist logregexpurllist

EXTRA_DIST = bannedextensionlist bannediplist bannedmimetypelist \
	 bannedregexpurllist bannedsitelist.in bannedurllist.in \
	 contentregexplist exceptioniplist exceptionsitelist \
	 exceptionurllist filtergroupslist greysitelist \
	 greyurllist pics bannedphraselist.in weightedphraselist.in \
	 exceptionphraselist.in bannediplist exceptioniplist urlregexplist \
	 exceptionregexpurllist exceptionextensionlist exceptionmimetypelist \
	 exceptionfilesitelist bannedregexpheaderlist headerregexplist \
	 exceptionfileurllist logsitelist logurllist logregexpurllist 

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
