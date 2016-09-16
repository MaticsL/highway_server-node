#!/bin/sh
#
# Startup script for highway
#
# chkconfig: - 86 16
# processname: highway
# description: highway proxy server
# pidfile: /var/run/highway.pid
#
### BEGIN INIT INFO
# Provides: highway
# Required-Start: $local_fs $remote_fs $network
# Required-Stop: $local_fs $remote_fs $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: start and stop highway
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

if [ -L $0 ]; then
    initscript=`/bin/readlink -f $0`
else
    initscript=$0
fi

# Additional environment file
sysconfig=`/bin/basename $initscript`

if [ -f /etc/sysconfig/$sysconfig ]; then
    . /etc/sysconfig/$sysconfig
fi

highway=${HIGHWAY-/var/www/nodejs/highway.js}
prog='highway'
pidfile=${PIDFILE-/var/run/highway.pid}
LOGDIR=${LOGDIR-/var/log/highway}
USER=${USER-nginx}
NODE=${NODE-/usr/bin/node}
MAXFDS=${MAXFDS-16383}

RETVAL=0

start() {
    echo -n $"Starting $prog: "

    [ -d ${LOGDIR} ] || mkdir -p ${LOGDIR}
    [ -f ${LOGDIR}/highway.log ] || touch ${LOGDIR}/highway.log && chown ${USER} ${LOGDIR}/highway.log
    [ -f ${LOGDIR}/error.log ] || touch ${LOGDIR}/error.log && chown ${USER} ${LOGDIR}/error.log

    touch ${pidfile} && chown ${USER}:${USER} ${pidfile}

    maxfds=`ulimit -n`; ulimit -n ${MAXFDS}
    daemon --pidfile=${pidfile} --user=${USER} ${NODE} "${highway} >> ${LOGDIR}/highway.log 2>> ${LOGDIR}/error.log & echo \$! > ${pidfile}"
    ulimit -n ${maxfds}

    RETVAL=$?
    echo
    return $RETVAL
}

stop() {
    echo -n $"Stopping $prog: "
    killproc -p ${pidfile} ${prog}
    RETVAL=$?
    echo
    [ $RETVAL = 0 ] && rm -f ${pidfile}
}

rh_status() {
    status -p ${pidfile} ${prog}
}

# See how we were called.
case "$1" in
    start)
        rh_status >/dev/null 2>&1 && exit 0
        start
        ;;
    stop)
        stop
        ;;
    status)
        rh_status
        RETVAL=$?
        ;;
    restart)
        stop
        start
        ;;
    *)
        echo $"Usage: $prog {start|stop|restart|status|help}"
        RETVAL=2
esac

exit $RETVAL
