# category: runtime
# title: Program running under a kernel thread's name
# indicator: raid5wq
cp /bin/sleep /usr/local/lib/.md-helper
nohup bash -c "exec -a '[raid5wq]' /usr/local/lib/.md-helper 3600" >/dev/null 2>&1 &
sleep 0.5
