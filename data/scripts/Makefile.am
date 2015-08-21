DISTCLEANFILES = Makefile.in

SUBDIRS= .

DATATOPDIR = $(datadir)/$(PACKAGE_NAME)/scripts

FLISTS = e2guardian logrotation bsd-init\
             solaris-init systemv-init\
	     e2guardian.service

EXTRA_DIST = e2guardian.in logrotation.in bsd-init.in\
             solaris-init.in systemv-init.in\
	     e2guardian.service.in

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(DATATOPDIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(DATATOPDIR)/$$l; \
	done

uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(DESTDIR)$(DATATOPDIR)/$$l ; \
	done

