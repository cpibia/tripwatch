#!/bin/sh
# Runs after install and upgrade, for deb and rpm alike. The service is not started here: it
# needs the bundle written by `tripwatch-sensor enroll`.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	if systemctl is-active --quiet tripwatch-sensor; then
		systemctl restart tripwatch-sensor || true
	fi
fi
