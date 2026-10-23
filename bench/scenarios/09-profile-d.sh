# category: persistence
# title: Login script in /etc/profile.d
# indicator: profile.d/bench.sh
echo 'nohup /usr/local/sbin/bench-agent >/dev/null 2>&1 &' >/etc/profile.d/bench.sh
