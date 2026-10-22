# category: persistence
# title: Libreria iniettata con /etc/ld.so.preload
# indicator: ld.so.preload
# A library that exists keeps every later command quiet, as a real implant would.
ldconfig -p | awk '/libz\.so\.1 / { print $NF; exit }' >/etc/ld.so.preload
