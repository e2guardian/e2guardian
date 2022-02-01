#!/bin/sh
PID=$(grep pid /etc/e2guardian/e2guardian.conf | cut -d " " -f3)

if [ -e $PID ];then
   rm $PID
fi

/inotify.sh &

e2guardian -N
