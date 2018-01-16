DISTCLEANFILES = Makefile.in \
		       default.conf 

DGDATADIR = $(DGCONFDIR)/downloadmanagers

SUBDIRS = .

FLISTS = default.conf



EXTRA_DIST = default.conf.in 

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(DGDATADIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DGDATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(DGDATADIR)/$$l; \
	done


uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(DGDATADIR)/$$l ; \
	done
