
- Fix bug #181 ERR_RESPONSE_HEADERS with bypass
- Fix bug #183 whitelist and identification 
- Fix bug #182 e2guardian systemd service does not support reload 
- Fix bug #178 (NTLM Messages)

February 2016
- Version 3.5.0
Summary of changes in this release (v3.5.0) can be found in e2guardian.release

January 2016
Many Improvements and bug fixes, big thanks to Chris Nighswonger for his help  
- Remove unused code
- Fix Bug #169 Mismached use of free()
- Fix Bug #162 Check missing dependency openssl
- Fix Bug #163 e2guardian -g causes segfault 

December 2016
- Fix Bug #157 (Code 400 log)
- Fix Bug #130 filtergroupslist not working with NTLM authentication (HTTPS) 

November 2016
- Fix Bug #135 SSL Bypass not working
- Fix Bug #156 Crash with url beyond 2048 characters (in list)

October 2016
- New blockedflash.swf version + source

September 2016
- Add Squid Log File Format

August 2016
- Fix Bug #119 readFromSocket incorrect error path
- Fix Bug #136 (Ignoring the body of 304 replies causes corrupted messages)
- New auth plugin - identification by header -

July 2016
- New logheadervalue option added 

June 2016
- Russian translation
- Update french translation 

March 2016
- Version 3.4.0.3
Summary of changes in this release (v3.4.0.3) can be found in e2guardian.release

- Fix segfault when weightedphrasemode not defined
- naughtynesslimit now defaults to 50 (previously undefined)

February 2016
- Fix ICAP with c-icap server, new option previewforce
- Version 3.4.0.2
- Fix bug #109 (bannedphraselist not working)

- Version 3.4.0.1
- Hotfixes bugs #103 #105 (segfault) 

January 2016
- Version 3.4.0
- weightedphrasemode now optional - defaults to 1
- allowemptyhostcert option added (optional)
- createlistcachefiles now defaults to off

December 2015
- new sslsiteregexplist added (optional)
- search term logic changed so banned_search_override works with both
  search block list and with weighted search term.
- list_flags checked on lookups to avoid segv when lists not present
- Fix SEGV when SSL connect fails - add logsslerrors option
- Fix certificate generation with hostnames longer than 64 bytes (bug #96)

November 2015
- Fix bug #96 Certificate Issues - requires X509_V_FLAG_TRUSTED_FIRST support in openssl
- Add SNI support to MITM - note only works with openssh 1.0.1e or higher
- Fix bux #94 new option textmimetypes
- Reports error on ssl_connect failure - extra message (160) added
- SSLMITM Upgrade sha1 to sha256

September 2015
- originalip off by default (complain about 400 Bad request URL is malformed) 
- Added, "namesuffix" option - one log file by instance (syslog) -

August 2015
Summary of changes in this release (v3.2.0) can be found in e2guardian.release

July 2015
- Fix bug #76 sslaccessdeniedaddress and reporting level < 3 
- Remove old & unused values 
- Remove max_upload option from e2guardian.conf 

June 2015
- Fix Bug #75 contentscanners commandlinescan broken and potential problem with the others 
- Fix bug #30 compilation issue with --program-prefix
- Security Fix: AV and empty access_denied_domain value break scan silently
- Fix bug #72 (wrong config file)
- Add new option: "xforwardedforfilterip" 
- Fix weighted phrases bug #15 
- Add brazilian translation 
- Code cleaning
- Add Czech translation
- New ssllegacylogic option (SSL lists greysslsitelist and bannedsslsitelist in separate files) default off
- Add SEARCHWORDS as default  
- Add SSL_EXTRA_LIST as default  
- Add LOCAL_LIST as default new option enablelocallists = on/off 
- Add TOTAL_BLOCK_LIST as default
- Fix e2 now can start with --enable-sslmitm=yes without ca certificat 

January 2015
- MITM cert checking re-enabled
- MITM cert checking can be turned on/off with mitmcheckcert option
- Optional nocheckcertsitelist introduced 

December 2014
- Version 3.1.2
- Several bug fixes
- MITM cert checking disabled to enable cross-platform working to address Google retirement of nosslsearch feature.

December 2014
- Version 3.1.1
MITM now working -  See notes/ssl_mitm for details
- Fix Segfault with filter_ports < auth plugins bug #44
- Fix e2guardianf1.conf and groupmode = 0 breaks identification bug #38

November 2014
- Fix blanket block not working bug

May/June 2014 
- CIDR format support added in IP lists
- Rooms facility updated - now includes room specific overide white lists
- New perroomdirectory option in e2guardian.conf added
- Backward compatible with perroombanneddirectory option.
- Hard coded room user/log messages removed and replaced with new items in language messages file.
- Reading of lists functions amended to accomodate reading of multiple types of lists from a single file.
- Fixes from 3.0.4 merged
- Fixes from 3.0.3 merged
- Start of development version 3.1
- Fix Compilation problem with --enable-dnsauth=yes

June/July 2014 - e2guardian 3.0.3
- Fix issue with urls ending in '//'
- Fix Compilation problem with --enable-dnsauth=yes

June 2014 - e2guardian 3.0.3
- Fix site truncation when total_block_list in use
- Error message now given when maxchildren is reached
- Fix gentle restart -  A '-g' gentle restart does not kill current connections but filter group config is re-read.
- Fix ugly check about "open room definitions"
- Information message should be given when e2guardian is reloaded 

Mai 2014
- Release 3.0.2 - It fixes some compile errors reported in v3.0.1

April 2014
- Release 3.0.1 - see e2guardian.release for details

February 2014
- Maxlogitemlength code moved into ConnectionHandler.cpp so as to prevent 
very large URLs corrupting log messages and to lower load on inter-process 
communication. 
- URL cache - Cache is now only checked (or added to) if URL is less than 2000 bytes and method is GET.
- Emtpy list set issue fixed - was causes failure of logging and URLcache processes when filtergroup was set to block all.

November 2013 - e2guardian 1.0.0.1
- mapportstoips conf option added - when off listens on every filterports on every IP address,
- when on maps filterports to filterip's, default on

First alpha version with E2BN Protex features added - See e2guardian.release for details.

September 2013 - e2guardian 1.0.0.0
- URLs with # no longer truncated when reading lists
- mapauthtoports conf option added - when off scans all auth plugs on every listening addr/port, when on maps auth plugins to addr/ports, default on
- Warning message about reporting level by Frederic Bourgeois
- Added, full banned URL, including parameters, for sslaccesdenied By frederic Bourgeois 
- Added, nonstandarddelimiter per filtergroupe By frederic Bourgeois
- Fix Libpcre crash by Russell coker from Debian
- Fix BSD crash (process forking out of control) By Philip Pearce and Martin Coco

For historical changes to DansGuardian see DGChangeLog
