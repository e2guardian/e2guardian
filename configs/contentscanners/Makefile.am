DISTCLEANFILES = Makefile.in \
		       clamdscan.conf icapscan.conf \
		       kavdscan.conf commandlinescan.conf

E2DATADIR = $(E2CONFDIR)/contentscanners

SUBDIRS = .


FLISTS =

if ENABLE_CLAMD
FLISTS += clamdscan.conf
endif

if ENABLE_AVASTD
FLISTS += avastdscan.conf
endif

if ENABLE_ICAP
FLISTS += icapscan.conf
endif

if ENABLE_KAVD
FLISTS += kavdscan.conf
endif

if ENABLE_COMMANDLINE
FLISTS += commandlinescan.conf
endif

EXTRA_DIST = clamdscan.conf.in avastdscan.conf.in icapscan.conf.in \
             kavdscan.conf.in commandlinescan.conf.in

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
