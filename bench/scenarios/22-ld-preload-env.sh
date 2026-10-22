# category: runtime
# title: Processo con LD_PRELOAD nell'ambiente
# indicator: bench-env.so
LD_PRELOAD=/usr/lib/bench-env.so nohup sleep 3600 >/dev/null 2>&1 &
