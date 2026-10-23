#!/bin/sh
# The bundle in /etc/tripwatch and the state in /var/lib/tripwatch are kept: reinstalling the
# package resumes the same chain without enrolling the host again.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
