#!/bin/sh
# dpkg passes "remove" on removal and "upgrade" on upgrade; rpm passes 0 on removal and 1 on
# upgrade. Only a removal stops the service.
set -e

case "$1" in
remove | purge | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now tripwatch-sensor || true
	fi
	;;
esac
