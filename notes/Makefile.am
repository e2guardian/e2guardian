DISTCLEANFILES = Makefile.in 

SUBDIRS = .

E2DATADIR = ${datadir}/doc/${PACKAGE}/notes

FLISTS = AuthPlugins \
    GeoLocation \
    HOWTO_Logger.md \
    ICAP_server_notes_for_implimenting_ICAP_client \
    LogFormatFiles \
    LogRequests \
    NEWIN_v4 \
    NEWIN_v5 \
    New_log_fields_in_log_format7-8.pdf \
    Upgrading_to_V5 \
    Upgrading_to_V5.4 \
    V5_Storyboard.pdf \
    V5_list_definition.pdf \
    V5_mode_comparison.pdf \
    cgi_bypass \
    dstats_format \
    e2guardian.release \
    extended_rooms \
    icap \
    lists_via_stdin \
    per_category_block_forms \
    port_auth \
    rotating_logs \
    ssl_mitm \
    template_variables 
	

EXTRA_DIST = 


install-data-local: 
	$(mkinstalldirs) $(E2DATADIR) && \
	for l in $(FLISTS) ; do \
		echo "$(INSTALL_DATA) $$l $(E2DATADIR)/$$l"; \
		$(INSTALL_DATA) $$l $(E2DATADIR)/$$l; \
	done

uninstall-local:
	for l in $(FLISTS) ; do \
		rm -f $(E2DATADIR)/$$l ; \
	done

