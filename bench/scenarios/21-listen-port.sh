# category: runtime
# title: Backdoor listening on port 31337
# indicator: 31337
nohup nc -lk -p 31337 >/dev/null 2>&1 &
