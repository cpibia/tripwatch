# Reference host for the detection benchmark: a Debian server with a WordPress site, tripwatch and
# the classic integrity and rootkit scanners, each with a baseline taken on the clean system.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      aide aide-common rkhunter debsums \
      cron e2fsprogs file iproute2 jq libcap2-bin lsof netcat-openbsd openssh-server procps sudo time \
 && rm -rf /var/lib/apt/lists/*

COPY fixture/ /
COPY tripwatch-sensor /usr/local/sbin/tripwatch-sensor
COPY judge /usr/local/bin/judge
COPY probe.sh /bench/probe.sh
COPY refs.sh /bench/refs.sh
COPY scenarios/ /bench/scenarios/

RUN chown -R www-data:www-data /var/www \
 && /bench/refs.sh \
 && /bench/probe.sh baseline
