authpluginsdir = $(DGCONFDIR)/authplugins

dist_authplugins_DATA = proxy-basic.conf ident.conf proxy-digest.conf proxy-header.conf

nodist_authplugins_DATA = ip.conf port.conf

EXTRA_DIST = ip.conf.in port.conf.in

if ENABLE_NTLM
dist_authplugins_DATA += proxy-ntlm.conf
else
EXTRA_DIST += proxy-ntlm.conf
endif

if PRT_DNSAUTH
dist_authplugins_DATA += dnsauth.conf
else
EXTRA_DIST += dnsauth.conf
endif
