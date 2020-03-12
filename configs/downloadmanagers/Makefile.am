DISTCLEANFILES = Makefile.in \
		       default.conf 

E2DATADIR = $(E2CONFDIR)/downloadmanagers

SUBDIRS = .

FLISTS = default.conf



EXTRA_DIST = default.conf.in 

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
	done


uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
	done
