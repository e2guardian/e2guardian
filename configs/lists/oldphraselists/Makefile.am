DISTCLEANFILES = Makefile.in

E2DATADIR = $(E2CONFDIR)/lists/oldphraselists
PHRASELISTS = badwords chat drugadvocacy gambling games goodphrases \
		googlesearches gore illegaldrugs intolerance legaldrugs \
		malware news nudism peer2peer personals pornography \
		proxies sport violence warezhacking weapons webmail \
		forums rta conspiracy domainsforsale idtheft safelabel \
		travel upstreamfilter secretsocieties translation music

install-data-local: 
	for l in $(PHRASELISTS); do \
		$(mkinstalldirs) $(DESTDIR)$(E2DATADIR)/$$l && \
		for f in $(srcdir)/$$l/weighted* $(srcdir)/$$l/exception* $(srcdir)/$$l/banned*; do \
		   if test -f $$f ; then \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(E2DATADIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(E2DATADIR)/$$l; \
	           fi \
		done \
	done

uninstall-local:
	for l in $(PHRASELISTS); do \
		for f in $(srcdir)/$$l/weighted* $(srcdir)/$$l/exception*; do \
	        	rm -f $(DESTDIR)$(E2DATADIR)/$$l/`basename $$f`; \
		done \
	done

dist-hook:
	for phrase in $(PHRASELISTS); do \
	  if test "$$phrase" = .; then :; else \
	    test -d $(distdir)/$$phrase \
	    || mkdir $(distdir)/$$phrase \
	    || exit 1; \
	    for f in $(srcdir)/$$phrase/weighted* $(srcdir)/$$phrase/banned* $(srcdir)/$$phrase/exception*; do \
	      if test -f $$f ; then \
	        cp -p $$f $(distdir)/$$phrase ;\
	      fi; \
	    done; \
	  fi; \
	done		
