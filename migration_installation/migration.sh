#!/bin/sh
# http://e2guardian.org/
# Migration and installation script 

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Make sure only root can run this script

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 
   exit 1
fi

# Make sure a binary exist

if [ ! -f ../src/e2guardian ]; then
   echo "No binary, compile first" 
   exit 1
fi

is_initial_configuration () { 	
        mkdir -p /etc/e2guardian
	mkdir -p /var/log/e2guardian
	cp init.d/e2guardian /etc/init.d
	cp logrotate.d/e2guardian /etc/logrotate.d/
	cp ../src/e2guardian /usr/sbin/
	cp basic/* /etc/e2guardian/
# rights
	chown -Rf e2guardian /etc/e2guardian
	chmod -Rf 700 /etc/e2guardian
	
	chown -Rf e2guardian /var/log/e2guardian
	chmod -Rf 700 /var/log/e2guardian
	
	chmod 755 /usr/sbin/e2guardian
}

is_migration_configuration () {
	echo "save and remove DG"
	mv -f /etc/dansguardian /etc/dansguardian.back
	mv -f /var/log/dansguardian /var/log/dansguardian.back
	# Debian only ?
	update-rc.d 2>/dev/null
	if [ $? = 1 ]; then 
		update-rc.d -f dansguardian remove
	else
		echo "DG init script still present, you MUST remove it after"

	fi
	# Make e2guardian configuration
	is_initial_configuration
	cp -Rf /etc/dansguardian.back/* /etc/e2guardian/
	chown -Rf e2guardian /etc/e2guardian
	if [ -f /etc/e2guardian/dansguardian.conf ]; then	
		cd /etc/e2guardian
		for i in *.* ; do sed -i 's/dansguardian/e2guardian/g' $i ; done
		for i in *.* ; do sed -i 's/dansguardian/e2guardian/g' $i ; done
		for i in dansguardian*;do mv $i e2guardian${i#dansguardian} ;done
	fi	
}

# Installing e2guardian init conf
echo "Installing generic e2guardian conf files"
echo "You have to configure e2guardian after"
echo "If some options seems missing take a look at http://e2guardian.org/"
sleep 3

useradd -r e2guardian 2>/dev/null

# No dg here ?

if [ ! -f /etc/dansguardian/dansguardian.conf ]; then	
	is_initial_configuration
else
	echo "DG is present, you MUST remove it after"
	is_migration_configuration
fi



# RCLeveling :
echo "Enabling rclevel for e2guardian" 
update-rc.d 2>/dev/null
if [ $? = 1 ]; then 
	update-rc.d e2guardian start 99 2 3 4 5 . stop 21 0 1 6 .
else
	echo "ed2guardian is installed but init script is missing"

fi

