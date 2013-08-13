MAINTAINERCLEANFILES = Makefile.in

DGDATADIR = $(DGCONFDIR)/lists/contentscanners

SUBDIRS = .

WLISTS = exceptionvirusmimetypelist exceptionvirusextensionlist \
         exceptionvirussitelist exceptionvirusurllist

EXTRA_DIST = $(WLISTS)

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
