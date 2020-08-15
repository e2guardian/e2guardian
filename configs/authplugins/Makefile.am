DISTCLEANFILES = Makefile.in

E2DATADIR = $(E2CONFDIR)/authplugins

SUBDIRS = .

FLISTS = proxy-basic.conf ident.conf ip.conf proxy-digest.conf \
	 port.conf pf-basic.conf

if ENABLE_NTLM
FLISTS += proxy-ntlm.conf
endif

if PRT_DNSAUTH
FLISTS += dnsauth.conf
endif


EXTRA_DIST = proxy-basic.conf ident.conf ip.conf proxy-ntlm.conf \
	     proxy-digest.conf port.conf dnsauth.conf

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
