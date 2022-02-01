#!/bin/bash
LISTS="/etc/e2guardian"
horodate=$(date +%d-%m-%Y_%H_%M)
if [ -d $LISTS ]
then
   while inotifywait -e modify,delete,create -r $LISTS --exclude \.swp
   do 
   # wait all modifications
     sleep 10
     horodate=$(date +%d-%m-%Y_%H_%M)
     /usr/sbin/e2guardian -r
     echo "RELOAD E2 $horodate: new files" >> /var/log/e2guardian/reloade2.log
     sleep 60
   done
fi

