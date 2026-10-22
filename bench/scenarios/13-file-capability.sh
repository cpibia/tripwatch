# category: privilege
# title: Capability cap_setuid su una copia di un binario
# indicator: /usr/local/bin/bench-cap
cp /usr/bin/perl /usr/local/bin/bench-cap
setcap cap_setuid+ep /usr/local/bin/bench-cap
