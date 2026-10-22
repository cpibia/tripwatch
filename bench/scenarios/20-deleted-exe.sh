# category: runtime
# title: Processo avviato da un eseguibile poi cancellato
# indicator: /tmp/.bench-agent
cp /bin/sleep /tmp/.bench-agent
nohup /tmp/.bench-agent 3600 >/dev/null 2>&1 &
sleep 0.5
rm -f /tmp/.bench-agent
