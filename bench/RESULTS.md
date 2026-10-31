# Detection benchmark

Commit `9fcf6ea`, 2026-10-31, container Debian GNU/Linux 12 (bookworm) on amd64, kernel 7.0.0-1014-aws. Tools compared: AIDE 0.18.3, rkhunter 1.4.6-11, debsums 3.0.2.1,
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

A tool **names** the attack when its output identifies the technique, beyond reporting the artifact added,
changed or removed: for tripwatch an alert of high or critical severity that mentions the artifact, raised by
the verifier on the snapshot compared with the baseline or by its real-time rules; for the others a new line
about the artifact that carries a judgement of the tool on it, a warning of rkhunter. AIDE and debsums report
changes only, so they never name. The same criterion applies to every tool.

**Noise** is measured on routine changes: for each tool, what it reports beyond the clean run (tripwatch: alerts;
AIDE: added, removed and changed entries; rkhunter: warnings; debsums: failed files). Fewer is better.

The control scenario, with no attack, produces no differences for any tool.

## Results per scenario

### Persistence

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| SSH key added to root | ✅ named | ✅ | ❌ | ❌ |
| New account with UID 0 | ✅ named | ✅ | ✅ named | ❌ |
| NOPASSWD sudo rule for www-data | ✅ named | ✅ | ❌ | ❌ |
| Job in /etc/cron.d | ✅ named | ✅ | ❌ | ❌ |
| Crontab of the web user | ✅ named | ✅ | ❌ | ❌ |
| Enabled systemd service | ✅ named | ✅ | ❌ | ❌ |
| systemd generator (runs as root at every boot) | ✅ named | ✅ | ❌ | ❌ |
| Library injected through /etc/ld.so.preload | ✅ named | ✅ | ✅ | ❌ |
| Login script in /etc/profile.d | ✅ named | ✅ | ❌ | ❌ |
| Line added to root's .bashrc | ✅ named | ✅ | ❌ | ❌ |
| Command planted in the SSH login script sshrc | ✅ named | ✅ | ❌ | ❌ |
| Root hook run when a network interface comes up | ✅ named | ✅ | ❌ | ❌ |
| Backdoor sourced from a bash completion fragment | ✅ named | ✅ | ❌ | ❌ |

### Privileges

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Setuid shell in /var/tmp | ✅ named | ✅ | ❌ | ❌ |
| Setuid shell in /run/lock (world-writable tmpfs) | ✅ named | ✅ | ❌ | ❌ |
| cap_setuid capability on a copy of a binary | ✅ named | ✅ | ❌ | ❌ |
| Backdoor protected with chattr +i | ✅ named | ✅ | ❌ | ❌ |

### System integrity

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Modified package binary | ✅ named | ✅ | ❌ | ✅ |
| PermitRootLogin enabled in sshd_config | ✅ named | ✅ | ❌ | ❌ |
| Executable owned by no package in /usr/local/bin | ✅ | ✅ | ❌ | ❌ |
| Link hijacking sudo from /usr/local/bin | ✅ | ✅ | ✅ named | ❌ |
| Hidden directory under /usr/lib | ✅ named | ✅ | ❌ | ❌ |

### Processes and network

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Process started from an executable later deleted | ✅ named | ❌ | ❌ | ❌ |
| Backdoor listening on port 31337 | ✅ | ❌ | ✅ named | ❌ |
| Process with LD_PRELOAD in its environment | ✅ | ❌ | ❌ | ❌ |
| Backdoor waiting on a packet socket, no port open | ✅ named | ✅ | ❌ | ❌ |
| Fileless implant run from memory (memfd) | ✅ named | ❌ | ❌ | ❌ |
| Program running under a kernel thread's name | ✅ | ❌ | ❌ | ❌ |

### Web applications

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Webshell in WordPress uploads | ✅ named | ✅ | ❌ | ❌ |
| GIF image with PHP code appended | ✅ named | ✅ | ❌ | ❌ |
| Backdoor injected into an existing PHP file | ✅ named | ✅ | ❌ | ❌ |
| .htaccess that runs images as PHP | ✅ named | ✅ | ❌ | ❌ |
| PHP saved by the application in a cache file, to be included later | ✅ named | ✅ | ❌ | ❌ |
| Card skimmer added to the site's JavaScript | ✅ named | ✅ | ❌ | ❌ |
| Backdoor in the web root with its function name split and escaped | ✅ named | ✅ | ❌ | ❌ |
| Core file changed to include remote code when a cookie is set | ✅ named | ✅ | ❌ | ❌ |
| Web shell opened by a bare short tag in a data file the application includes | ✅ named | ✅ | ❌ | ❌ |
| Code in a data file hidden behind a heredoc whose label is longer than usual | ✅ named | ✅ | ❌ | ❌ |
| Card skimmer in a theme with the field's name split into pieces | ✅ named | ✅ | ❌ | ❌ |
| Backdoor without a known signature in a file of a public plugin | ✅ named | ✅ | ❌ | ❌ |

### Limits: attacks between two checks, and traps

| Scenario | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Dropper run and deleted between two checks | ✅ named | ❌ | ❌ | ❌ |
| SSH key added, used and removed between two checks | ✅ named | ❌ | ❌ | ❌ |
| FIFO in place of the web user's authorized_keys | ✅ named | ✅ | ❌ | ❌ |
| Loader search path poisoned via ld.so.conf.d, then the config removed | ✅ named | ❌ | ❌ | ❌ |

## Noise from routine changes

Reported beyond the clean run; fewer is better.

| Routine change | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Update of a WordPress plugin, its version and sixty files rewritten | 0 | 0 | 0 | 0 |
| Installation of a package that ships a login hook | 1 | 6 | 0 | 0 |
| Rotation of the system logs, as logrotate does every night | 0 | 4 | 0 | 0 |
| Deploy that rewrites the site's code with a new release | 1 | 0 | 0 | 0 |

## Cost of a full check

Measured on the control scenario, in the same container.

| Tool | Time | Peak memory |
|---|--:|--:|
| tripwatch | 0.8 s | 33 MB |
| AIDE | 22.8 s | 41 MB |
| rkhunter | 81.4 s | 11 MB |
| debsums | 0.5 s | 13 MB |
