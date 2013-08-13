MAINTAINERCLEANFILES    = Makefile.in

DGDATADIR = $(DGCONFDIR)/lists/blacklists
BLACKLISTS = ads

install-data-local: 
	for l in $(BLACKLISTS); do \
		$(mkinstalldirs) $(DESTDIR)$(DGDATADIR)/$$l && \
		for f in $(srcdir)/$$l/domains* $(srcdir)/$$l/urls*; do \
		   if test -f $$f ; then \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(DGDATADIR)/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(DGDATADIR)/$$l; \
	           fi \
		done \
	done

uninstall-local:
	for l in $(BLACKLISTS); do \
		for f in $(srcdir)/$$l/domains* $(srcdir)/$$l/urls*; do \
	        	rm -f $(DESTDIR)$(DGDATADIR)/$$l/`basename $$f`; \
		done \
	done

dist-hook:
	for list in $(BLACKLISTS); do \
	  if test "$$list" = .; then :; else \
	    test -d $(distdir)/$$list \
	    || mkdir $(distdir)/$$list \
	    || exit 1; \
	    for f in $(srcdir)/$$list/domains* $(srcdir)/$$list/urls*; do \
	      if test -f $$f ; then \
	        cp -p $$f $(distdir)/$$list ;\
	      fi; \
	    done; \
	  fi; \
	done		
