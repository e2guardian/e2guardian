dmdir = $(DGCONFDIR)/downloadmanagers

nodist_dm_DATA = default.conf

if ENABLE_FANCYDM
nodist_dm_DATA += fancy.conf
endif

if ENABLE_TRICKLEDM
nodist_dm_DATA += trickle.conf
endif

EXTRA_DIST = default.conf.in fancy.conf.in trickle.conf.in
