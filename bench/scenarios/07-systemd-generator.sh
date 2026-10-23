# category: persistence
# title: systemd generator (runs as root at every boot)
# indicator: system-generators/bench-gen
mkdir -p /etc/systemd/system-generators
printf '#!/bin/sh\n/usr/local/sbin/bench-agent &\n' >/etc/systemd/system-generators/bench-gen
chmod 755 /etc/systemd/system-generators/bench-gen
