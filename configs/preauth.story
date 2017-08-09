function(pre-authcheck)
if(clientin,bannedclient) return setblock
if(clientin,exceptionclient) return setexception

function(thttps-pre-authcheck)
if(clientin,bannedclient) return setblock
if(clientin,exceptionclient) return setexception
