scandir = $(DGCONFDIR)/contentscanners
nodist_scan_DATA = 

if ENABLE_CLAMD
nodist_scan_DATA += clamdscan.conf
endif

if ENABLE_AVASTD
nodist_scan_DATA += avastdscan.conf
endif

if ENABLE_ICAP
nodist_scan_DATA += icapscan.conf
endif

if ENABLE_KAVD
nodist_scan_DATA += kavdscan.conf
endif

if ENABLE_COMMANDLINE
nodist_scan_DATA += commandlinescan.conf
endif

EXTRA_DIST = clamdscan.conf.in avastdscan.conf.in icapscan.conf.in \
             kavdscan.conf.in commandlinescan.conf.in
