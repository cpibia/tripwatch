#!/bin/sh
# dpkg passes "remove" on removal and "upgrade" on upgrade; rpm passes 0 on removal and 1 on
# upgrade. Only a removal stops the service.
set -e

case "$1" in
remove | purge | 0)
	# The running sensor reads this as it stops and tells the verifier it is being removed, in
	# its own signed chain: a second process sending now would fork that chain.
	if [ -d /var/lib/tripwatch ]; then
		touch /var/lib/tripwatch/removing || true
	fi
	if [ -d /run/systemd/system ]; then
		systemctl disable --now tripwatch-sensor || true
	fi
	;;
esac
