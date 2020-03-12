DISTCLEANFILES = Makefile.in 

E2DATADIR = $(E2CONFDIR)/lists/phraselists

MYSUBDIRS = chinesebig5 chinesegb2312 danish dutch french german italian japanese malay norwegian polish portuguese russian-1251 russian-koi8-r spanish swedish ukenglish 


#WLISTS = README
 

#install-data-local: 
#	$(mkinstalldirs) $(DESTDIR)$(E2DATADIR) && \
#		for l in $(WLISTS) ; do \
#		echo "$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l"; \
#		$(INSTALL_DATA) $$l $(DESTDIR)$(E2DATADIR)/$$l; \
#	done


#uninstall-local:
#	for l in $(WLISTS) ; do \
#		rm -f $(DESTDIR)$(E2DATADIR)/$$l ; \
#	done

PHRASELISTS = badwords chat drugadvocacy gambling games goodphrases \
		gore illegaldrugs intolerance \
		nudism personals pornography \
		proxies violence warezhacking weapons 
		

install-data-local: 
	for lang in $(MYSUBDIRS); do \
	for l in $(PHRASELISTS); do \
		if test -d $(srcdir)/$$lang/$$l ; then \
		$(mkinstalldirs) $(DESTDIR)$(E2DATADIR)/$$lang/$$l && \
		for f in $(srcdir)/$$lang/$$l/weighted* $(srcdir)/$$lang/$$l/exception* $(srcdir)/$$lang/$$l/banned*; do \
		   if test -f $$f ; then \
			echo "$(INSTALL_DATA) $$f $(DESTDIR)$(E2DATADIR)/$$lang/$$l"; \
			$(INSTALL_DATA) $$f $(DESTDIR)$(E2DATADIR)/$$lang/$$l; \
	           fi \
		done \
		fi \
	done \
	done 

uninstall-local:
	for lang in $(MYSUBDIRS); do \
	for l in $(PHRASELISTS); do \
		for f in $(srcdir)/$$lang/$$l/weighted* $(srcdir)/$$lang/$$l/exception*; do \
	        	rm -f $(DESTDIR)$(E2DATADIR)/$$lang/$$l/`basename $$f`; \
		done \
	done \
	done

dist-hook:
	for lang in $(MYSUBDIRS); do \
	for phrase in $(PHRASELISTS); do \
	  if test "$$phrase" = .; then :; else \
	    test -d $(distdir)/$$lang/$$phrase \
	    || mkdir $(distdir)/$$lang/$$phrase \
	    || exit 1; \
	    for f in $(srcdir)/$$lang/$$phrase/weighted* $(srcdir)/$$lang/$$phrase/banned* $(srcdir)/$$lang/$$phrase/exception*; do \
	      if test -f $$f ; then \
	        cp -p $$f $(distdir)/$$lang/$$phrase ;\
	      fi; \
	    done; \
	  fi; \
	done \
	done		


