# category: limits
# title: Dropper eseguito e cancellato tra due controlli
# indicator: /tmp/.bench-dropper
printf '#!/bin/sh\necho pwned >/dev/null\n' >/tmp/.bench-dropper
chmod 755 /tmp/.bench-dropper
/tmp/.bench-dropper
rm -f /tmp/.bench-dropper
