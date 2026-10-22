# category: limits
# title: Chiave SSH aggiunta, usata e rimossa tra due controlli
# indicator: bench-transient
# indicator: /root/.ssh/authorized_keys
mkdir -p /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITransientTransientTransientTransientTr bench-transient' >/root/.ssh/authorized_keys
rm -f /root/.ssh/authorized_keys
