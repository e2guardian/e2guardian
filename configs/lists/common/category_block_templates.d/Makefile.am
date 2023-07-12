DISTCLEANFILES = Makefile.in 

E2DATADIR = $(E2CONFDIR)/lists/common/category_block_templates.d

SUBDIRS = . 

WLISTS = README
 
EXTRA_DIST = 

install-data-local: 
	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
		for l in $(WLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
	done


uninstall-local:
	for l in $(WLISTS) ; do \
		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
	done
