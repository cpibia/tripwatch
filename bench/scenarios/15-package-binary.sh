# category: integrity
# title: Modified package binary
# indicator: /usr/bin/pinky
printf '\x00bench' >>/usr/bin/pinky
