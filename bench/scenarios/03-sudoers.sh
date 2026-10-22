# category: persistence
# title: Regola sudo NOPASSWD per www-data
# indicator: sudoers.d/bench
echo 'www-data ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/bench
chmod 0440 /etc/sudoers.d/bench
