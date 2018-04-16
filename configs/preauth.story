function(pre-authcheck)
if(clientin,bannedclient) return setblock
if(clientin,exceptionclient) return setexception
if(urlin,authexception) setexception
# allow authexceptions to go direct to avoid being blocked by any auth on squid
if(returnset) setgodirect

function(thttps-pre-authcheck)
if(clientin,bannedclient) return setblock
if(clientin,exceptionclient) return setexception
if(urlin,authexception) return setexception


function(icap-pre-authcheck)
