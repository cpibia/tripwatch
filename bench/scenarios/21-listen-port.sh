# category: runtime
# title: Backdoor in ascolto sulla porta 31337
# indicator: 31337
nohup nc -lk -p 31337 >/dev/null 2>&1 &
