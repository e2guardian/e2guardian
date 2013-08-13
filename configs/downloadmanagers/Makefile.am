MAINTAINERCLEANFILES = Makefile.in \
		       default.conf fancy.conf trickle.conf

DGDATADIR = $(DGCONFDIR)/downloadmanagers

SUBDIRS = .

FLISTS = default.conf

if ENABLE_FANCYDM
FLISTS += fancy.conf
endif

if ENABLE_TRICKLEDM
FLISTS += trickle.conf
endif

EXTRA_DIST = default.conf.in fancy.conf.in trickle.conf.in

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
