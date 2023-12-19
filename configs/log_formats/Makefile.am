DISTCLEANFILES = Makefile.in 

SUBDIRS = .

E2DATADIR = log_formats


FLISTS = logformat1 \
	logformat2 \
	logformat3 \
	logformat4 \
	logformat5 \
	logformat6 \
	logformat7 \
	logformat8 \
        requestlogformat

EXTRA_DIST = 


install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(E2CONFDIR)/$(E2DATADIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2CONFDIR)/$(E2DATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2CONFDIR)/$(E2DATADIR)/$$l; \
	done

uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(E2CONFDIR)/$(E2DATADIR)/$$l ; \
	done

