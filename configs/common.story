# Storyboard library file

# For ease of upgrade DO NOT CHANGE THIS library file 
# Make your function changes by overriding functions
# in the site.story file - for site wide changes
# and in filtergroup specific story file - see examplef1.story
#
# This library is built to largely duplicate the logic in V4
# 
# Many e2guardian[f1].conf flags are replaced by overiding
# library functions - see site.story and examplef1.story
#
# Simple functions are defined which control the logic flow and the
# lists that are used.  See notes/Storyboard for details.
#
# The entry point in v5 for standard filtering is 'checkrequest'
#
# Entry function called by proxy module to check http request
function(checkrequest)
if(viruscheckset) checknoscanlists
if(bypassallowset) checknobypasslists
if(exceptionset) return true
if(fullurlin,searchterms) setsearchterm
ifnot(greyset) returnif localcheckrequest
if(connect) return sslrequestcheck
ifnot(greyset) returnif exceptioncheck
ifnot(greyset) greycheck
ifnot(greyset) returnif bannedcheck
if(fullurlin, change) setmodurl
if(true) returnif embeddedcheck
if(headerin,headermods) setmodheader
if(fullurlin, addheader) setaddheader
if(searchin,override) setexception
if(returnset) return setdone
if(searchin,banned) return setblock
if(fullurlin,redirect) return setredirect
if(true) setgrey


# Entry function called by proxy module to check http response
function(checkresponse)
if(exceptionset) return false
if(viruscheckset) checknoscantypes
if(urlin,exceptionfile) return false
if(true) return checkfiletype

# Entry function called by THTTPS module to check https request
function(thttps-checkrequest)
if(true) returnif localsslrequestcheck
if(true) returnif sslrequestcheck
ifnot(hassniset) checksni

# Entry function called by ICAP module to check reqmod
function(icap-checkrequest)
#unless blocked or redirect or connect - leave logging for RESPMOD
if(connect) return icapsslrequestcheck
ifnot(greyset) icap-checkrequest2
if(redirectset) return true
ifnot(blockset) setnolog

function(icap-checkrequest2)
if(viruscheckset) checknoscanlists
if(bypassallowset) checknobypasslists
if(exceptionset) return true
if(fullurlin,searchterms) setsearchterm
ifnot(greyset) returnif localcheckrequest
ifnot(greyset) returnif exceptioncheck
ifnot(greyset) greycheck
ifnot(greyset) returnif bannedcheck
if(fullurlin, change) setmodurl
if(true) returnif embeddedcheck
if(headerin,headermods) setmodheader
if(fullurlin, addheader) setaddheader
if(searchin,override) return setgrey
if(searchin,banned) return setblock
if(true) setgrey

# Entry function called by ICAP module to check respmod
function(icap-checkresponse)
if(viruscheckset) checknoscanlists
if(true) return checkresponse

# Checks embeded urls
#  returns true if blocked, otherwise false
function(embeddedcheck)
if(embeddedin, localexception) return false
if(embeddedin, localgrey) return false
if(embeddedin, localbanned) return setblock
if(embeddedin, exception) return false
if(embeddedin, grey) return false
if(embeddedin, banned) return setblock

# Local checks
#  returns true if matches local exception or banned
function(localcheckrequest)
if(connect) return localsslrequestcheck
ifnot(greyset) returnif localexceptioncheck
ifnot(greyset) localgreycheck
ifnot(greyset) returnif localbannedcheck
if(searchin,localbanned) return setblock


# Local SSL checks
#  returns true if matches local exception 
function(localsslrequestcheck)
if(sitein, localexception) return setexception
if(sitein, localgreyssl) returnif sslcheckmitm
if(sitein, localbanned) true
ifnot(returnset) return false
if(true) returnif sslcheckmitm
if(true) return setblock

# SSL site replace (used instead of dns kulge)
#  returns true on match and successful replacement
function(sslreplace)
if(fullurlin,sslreplace) return setconnectsite
if(true) return false

# Local grey check
#  returns true on match
function(localgreycheck)
if(urlin, localgrey) return setgrey

# Local banned check
#  returns true on match
function(localbannedcheck)
if(urlin, localbanned) return setblock

# Local exception check
#  returns true on match
function(localexceptioncheck)
if(urlin, localexception) return setexception

# Exception check
#  returns true on match
function(exceptioncheck)
if(urlin, exception) return setexception
if(refererin,refererexception) return setexception
if(headerin, exceptionheader) return setexception
if(useragentin, exceptionuseragent) return setexception
ifnot(urlin,embededreferer) return false
if(embeddedin,refererexception) return setexception

# SSL Exception check
#  returns true on match
function(sslexceptioncheck)
if(sitein, exception) return setexception
if(headerin, exceptionheader) return setexception
if(useragentin, exceptionuseragent) return setexception
if(true) return false

# Greylist check
#  returns true on match
function(greycheck)
if(urlin, grey) return setgrey

# Banned list check
#  returns true on match
function(bannedcheck)
if(true) returnif checkblanketblock
if(urlin, banned) return setblock
if(urlin,bannedextension) return setblock
if(useragentin, banneduseragent) return setblock
if(headerin, bannedheader) return setblock

# Local SSL list(s) check
#  returns true on match
function(localsslcheckrequest)
if(sitein, localexception) return setexception
#if(sitein, localbanned) return setblock

# Check whether to go MITM
#  returns true if yes, false if no
function(sslcheckmitm)
# use next line to have general MITM
if(true) return sslcheckmitmgeneral
# use next line instead of last to limit MITM to greylist
#if(true) return sslcheckmitmgreyonly

# Always go MITM
#  returns true if yes, false if no
function(sslcheckmitmgeneral)
if(true) setgomitm
ifnot(returnset) return false
if(sitein, nocheckcert) setnocheckcert
if(true) sslreplace
if(true) return true

# Only go MITM when in greyssl list
#  returns true if yes, false if no
function(sslcheckmitmgreyonly)
if(sitein, greyssl) setgomitm
ifnot(returnset) return false
if(sitein, nocheckcert) setnocheckcert
if(true) sslreplace
if(true) return true

# SSL request check
#  returns true if exception or gomitm
function(sslrequestcheck)
if(true) returnif sslexceptioncheck
if(true) returnif sslcheckmitm
if(sitein, banned) return setblock
if(true) sslreplace
ifnot(returnset) returnif sslcheckblanketblock
if(true) setgrey

function(checknoscanlists)
if(urlin,exceptionvirus) unsetviruscheck

function(checknoscantypes)
if(mimein,exceptionvirus) return unsetviruscheck
if(extensionin,exceptionvirus) return unsetviruscheck

function(checknobypasslists)
if(urlin,bannedbypass) return unsetbypassallow

# ICAP SSL request check
#  returns true if exception 
function(icapsslrequestcheck)
if(true) returnif icapsquidbump
if(true) returnif sslexceptioncheck
if(true) sslreplace
if(sitein, banned) return setblock

# Blanket block
#  returns true if to block
#  Placeholder function - overide in fn.story
function(checkblanketblock)

# SSL Blanket block
#  returns true if to block
#  Placeholder function - overide in fn.story
function(sslcheckblanketblock)

# ICAP Squid bump
#  override in site.story to return true if bump is being deployed on squid
function(icapsquidbump)

# File type blocking
#  returns true if blocking
# Default uses banned lists and allows all others
# Overide in site.story or fn.story if only types in exception file type lists 
# are to be allowed
function(checkfiletype)
if(mimein, bannedmime) return setblock
if(extensionin, bannedextension) return setblock

# SNI checking - determines default action when no SNI or TSL is present on a 
#    THTTPS connection
# Default blocks all requests with TLS or SNI absent that are not ip site exceptions
function(checksni)
ifnot(tls,,511) return setblock
ifnot(hassniset,,512) return setblock
