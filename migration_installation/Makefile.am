MAINTAINERCLEANFILES = Makefile.in \
                       installation_or_migration_from_dg.sh 

# SUBDIRS =  .

if NEED_CSCONFIGS
endif

FLISTS = installation_or_migration_from_dg.sh 

EXTRA_DIST = installation_or_migration_from_dg.sh.in

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

