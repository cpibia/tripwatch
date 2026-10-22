# category: persistence
# title: Servizio systemd abilitato
# indicator: bench-backdoor.service
cat >/etc/systemd/system/bench-backdoor.service <<'UNIT'
[Service]
ExecStart=/usr/local/sbin/bench-agent
[Install]
WantedBy=multi-user.target
UNIT
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -s /etc/systemd/system/bench-backdoor.service /etc/systemd/system/multi-user.target.wants/bench-backdoor.service
