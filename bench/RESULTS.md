# Detection benchmark

Commit `6aafbed`, 2026-10-28, container Debian GNU/Linux 12 (bookworm) on amd64, kernel 7.0.0-1017-azure. Tools compared: AIDE 0.18.3, rkhunter 1.4.6-11, debsums 3.0.2.1,
with the default configuration of their Debian packages. Regenerate with `bench/run.sh`.

## Method

Every scenario starts from a clean container, the same for all: a Debian host with a WordPress site, on
which every tool has already taken its baseline. The scenario applies the attack, then every tool runs
once. A tool **detects** the scenario when the lines of its output that mention the artifact of the
attack (a path, the comment of a key, a port) differ from those of the baseline: something new appeared
or something known changed. For tripwatch the JSON objects that contain the artifact are compared: those
of the snapshot, where the final judgement belongs to the verifier and we measure whether the data
arrives, and the alerts the real-time rules of the verifier raise on what the watchers of the sensor reported while
the scenario ran, the watchers being started after a first snapshot as in daemon mode. Process events
need a kernel with the process connector: the run says which kernel it had.
**Blocked** means the tool did not finish within 900 s.

The control scenario, with no attack, produces no differences for any tool.

## Results per scenario

### Persistence

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| SSH key added to root | ✅ | ✅ | ❌ | ❌ |
| New account with UID 0 | ✅ | ✅ | ✅ | ❌ |
| NOPASSWD sudo rule for www-data | ✅ | ✅ | ❌ | ❌ |
| Job in /etc/cron.d | ✅ | ✅ | ❌ | ❌ |
| Crontab of the web user | ✅ | ✅ | ❌ | ❌ |
| Enabled systemd service | ✅ | ✅ | ❌ | ❌ |
| systemd generator (runs as root at every boot) | ✅ | ✅ | ❌ | ❌ |
| Library injected through /etc/ld.so.preload | ✅ | ✅ | ✅ | ❌ |
| Login script in /etc/profile.d | ✅ | ✅ | ❌ | ❌ |
| Line added to root's .bashrc | ✅ | ✅ | ❌ | ❌ |

### Privileges

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Setuid shell in /var/tmp | ✅ | ✅ | ❌ | ❌ |
| Setuid shell in /run/lock (world-writable tmpfs) | ✅ | ✅ | ❌ | ❌ |
| cap_setuid capability on a copy of a binary | ✅ | ✅ | ❌ | ❌ |
| Backdoor protected with chattr +i | ✅ | ✅ | ❌ | ❌ |

### System integrity

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Modified package binary | ✅ | ✅ | ❌ | ✅ |
| PermitRootLogin enabled in sshd_config | ✅ | ✅ | ❌ | ❌ |
| Executable owned by no package in /usr/local/bin | ✅ | ✅ | ❌ | ❌ |
| Link hijacking sudo from /usr/local/bin | ✅ | ✅ | ✅ | ❌ |
| Hidden directory under /usr/lib | ✅ | ✅ | ❌ | ❌ |

### Processes and network

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Process started from an executable later deleted | ✅ | ❌ | ❌ | ❌ |
| Backdoor listening on port 31337 | ✅ | ❌ | ✅ | ❌ |
| Process with LD_PRELOAD in its environment | ✅ | ❌ | ❌ | ❌ |
| Backdoor waiting on a packet socket, no port open | ✅ | ✅ | ❌ | ❌ |
| Fileless implant run from memory (memfd) | ✅ | ❌ | ❌ | ❌ |
| Program running under a kernel thread's name | ✅ | ❌ | ❌ | ❌ |

### Web applications

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Webshell in WordPress uploads | ✅ | ✅ | ❌ | ❌ |
| GIF image with PHP code appended | ✅ | ✅ | ❌ | ❌ |
| Backdoor injected into an existing PHP file | ✅ | ✅ | ❌ | ❌ |
| .htaccess that runs images as PHP | ✅ | ✅ | ❌ | ❌ |
| PHP saved by the application in a cache file, to be included later | ✅ | ✅ | ❌ | ❌ |
| Card skimmer added to the site's JavaScript | ✅ | ✅ | ❌ | ❌ |
| Backdoor in the web root with its function name split and escaped | ✅ | ✅ | ❌ | ❌ |
| Core file changed to include remote code when a cookie is set | ✅ | ✅ | ❌ | ❌ |

### Limits: attacks between two checks, and traps

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Dropper run and deleted between two checks | ✅ | ❌ | ❌ | ❌ |
| SSH key added, used and removed between two checks | ✅ | ❌ | ❌ | ❌ |
| FIFO in place of the web user's authorized_keys | ✅ | ✅ | ❌ | ❌ |

## Cost of a full check

Measured on the control scenario, in the same container.

| Tool | Time | Peak memory |
|---|--:|--:|
| tripwatch | 1.3 s | 28 MB |
| AIDE | 49.5 s | 39 MB |
| rkhunter | 151.1 s | 11 MB |
| debsums | 1.1 s | 13 MB |
