#!/bin/sh
# Runs after install and upgrade, for deb and rpm alike. The service is not started here: it
# needs the bundle written by `tripwatch-sensor enroll`.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	if systemctl is-active --quiet tripwatch-sensor; then
		# The running sensor reads this as it stops and reports the stop as an update.
		if [ -d /var/lib/tripwatch ]; then
			touch /var/lib/tripwatch/updating || true
		fi
		systemctl restart tripwatch-sensor || true
	fi
fi
