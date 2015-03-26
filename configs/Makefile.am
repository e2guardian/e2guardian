DISTCLEANFILES = Makefile.in \
e2guardian.conf \
e2guardianf1.conf

SUBDIRS = lists downloadmanagers authplugins .

if NEED_CSCONFIGS
SUBDIRS += contentscanners
endif

FLISTS = e2guardian.conf e2guardianf1.conf

EXTRA_DIST = e2guardian.conf.in e2guardianf1.conf.in

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

