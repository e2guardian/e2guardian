#! /bin/sh
# Startup script for e2guardian
# description: A web content filtering plugin for web \
#              proxies, developed to filter using lists of \
#              banned phrases, MIME types, filename \
#              extensions and PICS labling.
# processname: e2guardian
# pidfile: /var/run/e2guardian.pid
# config: /etc/e2guardian/dansguardian.conf
### BEGIN INIT INFO
# Provides:          e2guardian
# Required-Start:    $remote_fs $network $syslog
# Required-Stop:     $remote_fs $network $syslog
# Default-Start:     2 3 4 5 
# Default-Stop:      0 1 6 
# Description: Starts e2guardian content proxy 
# short-description: e2guardian configuration
### END INIT INFO

#include lsb functions
. /lib/lsb/init-functions

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/e2guardian
NAME=e2guardian
DESC="e2guardian"

CONFFILELOCATION=/etc/e2guardian/
#BINARYLOCATION=/usr/sbin/
#PIDDIR=/var/run/

grep -q ^UNCONFIGURED ${CONFFILELOCATION}e2guardian.conf && {
cat <<EOF
        e2guardian has not been configured!
        Please edit ${CONFFILELOCATION}e2guardian.conf manually then rerun
        this script.
EOF
exit; }

test -x $DAEMON || exit 0
test -f ${CONFFILELOCATION}e2guardian.conf || exit 0

set -e

case "$1" in
  start)
	log_daemon_msg "Starting $DESC" "$NAME"
	test -d /var/lock/subsys || mkdir -p /var/lock/subsys
	start-stop-daemon --start --quiet --pidfile /var/run/$NAME.pid \
		--exec $DAEMON || log_end_msg 1
	log_end_msg 0
	;;
  stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	start-stop-daemon --stop --quiet --retry 15 --oknodo --pidfile /var/run/$NAME.pid \
		--exec $DAEMON || log_end_msg 1
	log_end_msg 0
	;;
  reload)
	log_action_begin_msg "Reloading $DESC configuration..."
	echo "Reloading $DESC configuration files."
	start-stop-daemon --stop --signal 1 --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON || log_action_end_msg 1
	log_action_end_msg 0
  	;;
  restart|force-reload)
	#
	#	If the "reload" option is implemented, move the "force-reload"
	#	option to the "reload" entry above. If not, "force-reload" is
	#	just the same as "restart".
	#
	log_daemon_msg "Restarting $DESC" "$NAME"
	start-stop-daemon --stop --quiet --retry 15 --oknodo --pidfile \
		/var/run/$NAME.pid --exec $DAEMON || log_end_msg 1
	start-stop-daemon --start --quiet --pidfile \
		/var/run/$NAME.pid --exec $DAEMON || log_end_msg 1
	log_end_msg 0
	;;
  *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	log_action_msg "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
