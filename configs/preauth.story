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
