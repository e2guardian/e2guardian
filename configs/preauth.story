function(pre-authcheck)
if(clientin,bannedclient) return setblock
if(clientin,exceptionclient) return setexception
if(urlin,authexception) setexception
# allow authexceptions to go direct to avoid being blocked by any auth on squid
if(returnset) setgodirect
ifnot(connect) return
if(sitein,nomitm) return setnomitm
ifnot(useragentin,browser) unsetautomitm

function(thttps-pre-authcheck)
if(sitein,nomitm) setnomitm
if(clientin,bannedclient) return setblock
if(clientin,exceptionclient) return setexception
if(urlin,authexception) return setexception


function(icap-pre-authcheck)

# Functions for use by auth plugins to determine filtergroup - NEW in v5.4

function(defaultusermap)
if(userin,defaultusermap) return setgroup

#Each auth plugin that uses a list has its own entry function
# and returns true if filtergroup is matched and set and false if not found.

# Currently auth plugins which used the filtergrouplist in pre-v5.4 are set to use the default filtergrouplist so as to be backward compatible.

# However, now each plugin can have it's own list.  To do this, define a new maplist in e2guardian.conf named as say 'basicmap' and then replace
# 'if(true) return defaultusermap' with 'if(userin,basicmap) return setgroup'.  More complex logic is now possible if required.

function(auth_proxy_basic)
if(true) return defaultusermap

function(auth_proxy_header)
if(true) return defaultusermap

function(auth_proxy_ident)
if(true) return defaultusermap

function(auth_proxy_ntlm)
if(true) return defaultusermap

function(auth_proxy_digest)
if(true) return defaultusermap

function(auth_ip)
if(userin,ipmap) return setgroup

function(auth_port)
if(userin,portmap) return setgroup

function(auth_icap)  // non-plugin auth for ICAP - function name is hard-coded
if(true) return defaultusermap

