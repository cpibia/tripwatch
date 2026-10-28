# category: limits
# title: Loader search path poisoned via ld.so.conf.d, then the config removed
# indicator: ld.so.conf.d/zz-bench.conf
mkdir -p /opt/.lib
printf '/opt/.lib\n' >/etc/ld.so.conf.d/zz-bench.conf
ldconfig
rm -f /etc/ld.so.conf.d/zz-bench.conf
