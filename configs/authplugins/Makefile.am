DISTCLEANFILES = Makefile.in

E2DATADIR = $(E2CONFDIR)/authplugins

SUBDIRS = .

FLISTS = ident.conf ip.conf \
	 port.conf pf-basic.conf 

if PRT_DNSAUTH
FLISTS += dnsauth.conf
endif


EXTRA_DIST = ident.conf ip.conf \
	     port.conf dnsauth.conf pf-basic.conf

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
