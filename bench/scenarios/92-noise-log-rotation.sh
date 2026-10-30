# category: noise
# title: Rotation of the system logs, as logrotate does every night
# indicator: /var/log/dpkg.log
for f in /var/log/dpkg.log /var/log/alternatives.log /var/log/apt/history.log /var/log/apt/term.log; do
  [ -f "$f" ] || continue
  [ -f "$f.1" ] && gzip -f "$f.1"
  mv "$f" "$f.1"
  : >"$f"
done
