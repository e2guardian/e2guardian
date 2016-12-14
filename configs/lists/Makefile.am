SUBDIRS = phraselists . authplugins bannedrooms

if NEED_CSLISTS
SUBDIRS += contentscanners
endif
if NEED_DMLISTS
SUBDIRS += downloadmanagers
endif

listdir = $(DGCONFDIR)/lists

dist_list_DATA = \
	nocheckcertsitelist \
	bannedextensionlist bannediplist bannedmimetypelist \
	bannedregexpurllist \
	bannedsearchlist bannedsslsitelist \
	contentregexplist exceptioniplist exceptionsitelist \
	exceptionurllist filtergroupslist greysitelist \
	greyurllist pics urlregexplist \
	exceptionregexpurllist exceptionextensionlist exceptionmimetypelist \
	exceptionfilesitelist bannedregexpheaderlist headerregexplist \
	exceptionfileurllist logsitelist logurllist logregexpurllist \
	addheaderregexplist greysslsitelist \
	localbannedsearchlist localbannedsitelist localbannedsslsitelist \
	localbannedurllist localexceptionsitelist localexceptionurllist \
	localgreysitelist localgreysslsitelist localgreyurllist \
	refererexceptionsitelist refererexceptionurllist searchregexplist \
	embededreferersitelist embededrefererurllist \
	authexceptionsitelist authexceptionurllist \
	urlredirectregexplist sslsiteregexplist

nodist_list_DATA =		\
	bannedphraselist	\
	bannedsitelist		\
	bannedurllist		\
	exceptionphraselist	\
	weightedphraselist

EXTRA_DIST =			\
	bannedphraselist.in	\
	bannedsitelist.in	\
	bannedurllist.in	\
	exceptionphraselist.in	\
	weightedphraselist.in
