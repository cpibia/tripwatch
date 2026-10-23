# category: privilege
# title: cap_setuid capability on a copy of a binary
# indicator: /usr/local/bin/bench-cap
cp /usr/bin/perl /usr/local/bin/bench-cap
setcap cap_setuid+ep /usr/local/bin/bench-cap
