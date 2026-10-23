# category: integrity
# title: Hidden directory under /usr/lib
# indicator: /usr/lib/.bench
mkdir -p /usr/lib/.bench
cp /bin/true /usr/lib/.bench/kworker
