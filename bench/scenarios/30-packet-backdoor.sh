# category: runtime
# title: Backdoor waiting on a packet socket, no port open
# indicator: /usr/local/sbin/udev-netd
# Backdoors of this kind read every frame through AF_PACKET and wake on a magic packet, so no
# listening port ever shows.
cp /usr/bin/perl /usr/local/sbin/udev-netd
setsid /usr/local/sbin/udev-netd -e 'socket(my $s, 17, 3, 0x0300) or die; sleep 3600' </dev/null >/dev/null 2>&1 &
sleep 1
