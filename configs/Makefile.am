MAINTAINERCLEANFILES = Makefile.in \
                       dansguardian.conf dansguardianf1.conf

SUBDIRS = lists downloadmanagers authplugins .

if NEED_CSCONFIGS
SUBDIRS += contentscanners
endif

FLISTS = dansguardian.conf dansguardianf1.conf

EXTRA_DIST = dansguardian.conf.in dansguardianf1.conf.in

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(DGCONFDIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DGCONFDIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(DGCONFDIR)/$$l; \
	done

uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(DGCONFDIR)/$$l ; \
	done

