#!/bin/sh
set -eu
mkdir -p /run/sshd
touch /var/log/lab-auth.log
ssh-keygen -A >/dev/null
rsyslogd -f /etc/rsyslog-lab.conf
/usr/sbin/sshd -t
/usr/sbin/sshd
exec /init
