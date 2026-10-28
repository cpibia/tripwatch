# category: runtime
# title: Process with LD_PRELOAD in its environment
# indicator: bench-env.so
LD_PRELOAD=/usr/lib/bench-env.so nohup sleep 3600 >/dev/null 2>&1 &
