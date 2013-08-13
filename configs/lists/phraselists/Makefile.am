MAINTAINERCLEANFILES    = Makefile.in

DGDATADIR = $(DGCONFDIR)/lists/phraselists
PHRASELISTS = badwords chat drugadvocacy gambling games goodphrases \
		googlesearches gore illegaldrugs intolerance legaldrugs \
		malware news nudism peer2peer personals pornography \
		proxies sport violence warezhacking weapons webmail \
		forums rta conspiracy domainsforsale idtheft safelabel \
		travel upstreamfilter secretsocieties translation music

install-data-local: 
	for l in $(PHRASELISTS); do \
		$(mkinstalldirs) $(DESTDIR)$(DGDATADIR)/$$l && \
		for f in $(srcdir)/$$l/weighted* $(srcdir)/$$l/exception* $(srcdir)/$$l/banned*; do \
		   if test -f $$f ; then \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(DGDATADIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(DGDATADIR)/$$l; \
	           fi \
		done \
	done

uninstall-local:
	for l in $(PHRASELISTS); do \
		for f in $(srcdir)/$$l/weighted* $(srcdir)/$$l/exception*; do \
	        	rm -f $(DESTDIR)$(DGDATADIR)/$$l/`basename $$f`; \
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
