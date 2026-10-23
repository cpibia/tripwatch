# tripwatch

tripwatch detects unauthorized changes on servers, whatever runs on them. It watches what an
attacker changes to get in and to stay: new privileged accounts, existing accounts promoted (a
privileged group by GID or by sudoers rule, a password or shell enabled, a changed UID), SSH keys,
persistence in cron, systemd and startup scripts, setuid binaries and immutable files, system
files that no longer match their package, processes started from deleted or hidden executables,
unexpected outbound connections, application code changed without a deploy.

It is stack-agnostic. The core knows nothing about PHP, Python, Java or Rust: stack-specific
checks live in profiles that switch on when automatic discovery finds the matching technology. It
runs on plain hosts, Docker hosts, Kubernetes nodes and AWS Fargate.

## Contents

- [How it works](#how-it-works)
- [Installation](#installation)
  - [1. Verifier](#1-verifier)
  - [2. Sensor](#2-sensor)
  - [3. Enrollment](#3-enrollment)
  - [Kubernetes](#kubernetes)
  - [Building from source](#building-from-source)
- [Update and upgrade](#update-and-upgrade)
  - [New releases](#new-releases)
  - [Installed versions](#installed-versions)
  - [Upgrading the verifier](#upgrading-the-verifier)
  - [Upgrading the sensor](#upgrading-the-sensor)
  - [Removing](#removing)
- [What the sensor collects](#what-the-sensor-collects)
- [Real-time events](#real-time-events)
- [Web stack](#web-stack)
- [Applications and databases](#applications-and-databases)
- [Web server logs](#web-server-logs)
- [Detection compared](#detection-compared)
- [Trust model](#trust-model)
- [Known limits](#known-limits)
- [Verifier](#verifier)
- [Sensor](#sensor)
- [Roadmap](#roadmap)
- [Status](#status)
- [License](#license)

## How it works

```
 monitored server                                   dedicated machine
┌──────────────────────────────┐                   ┌──────────────────────────────┐
│ tripwatch-sensor             │ signed and        │ tripwatch-verifier           │
│  collects: state, events,    │ hash-chained      │  baselines and manifests     │
│  logs                        │ ────────────────▶ │  rules, correlation,         │
│  decides: nothing            │ push over mTLS    │  alerts                      │
└──────────────────────────────┘                   └──────────────────────────────┘
```

- **The sensor only observes.** It is a static Go binary with no dependencies, so it also runs on
  old or unpatched distributions. It sends a heartbeat every minute, a full state snapshot every
  hour and, on Linux, the changes to critical paths and the suspicious process starts as they
  happen.
- **The verifier decides, off the server.** Baselines and build manifests live where an attacker
  with root on a monitored server cannot rewrite them. The verifier holds no credentials to log
  into the servers: the sensors push their data to it.
- **Every message is signed and linked to the previous one.** A lost, replayed or forged message
  breaks the chain, and a silent sensor is already an alert.

A file is legitimate only if it traces back to the system package manager, to a signed deploy
manifest produced by the build (checked against the lockfile: `composer.lock`,
`package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`, ...) or to a container image digest.

## Installation

Every [release](https://github.com/cpibia/tripwatch/releases) publishes the sensor as `.deb` and
`.rpm` packages and the verifier as a container image (`ghcr.io/cpibia/tripwatch-verifier`).
Nothing needs to be cloned or compiled on the servers. The commands below always fetch the latest
release; each release also keeps its files with the version in the name.

### 1. Verifier

You need a dedicated machine with Docker (a small VPS is enough), outside the servers you will
monitor, and a DNS name pointing to it, here `tripwatch.example.net`.

```sh
mkdir tripwatch && cd tripwatch
curl -fsSLO https://github.com/cpibia/tripwatch/releases/latest/download/docker-compose.yml
curl -fsSL -o .env https://github.com/cpibia/tripwatch/releases/latest/download/verifier.env.example
```

In `.env` set at least the name the sensors will use, the public addresses and the
first user:

```sh
TRIPWATCH_VERSION=latest
TRIPWATCH_HOSTNAMES=tripwatch.example.net
TRIPWATCH_PUBLIC_INGEST_URL=https://tripwatch.example.net:8443/v1/envelopes
TRIPWATCH_PUBLIC_UI_URL=https://tripwatch.example.net
TRIPWATCH_ADMIN_EMAIL=ops@example.net
TRIPWATCH_ADMIN_PASSWORD=a-password-of-12-characters-or-more
```

```sh
docker compose up -d
```

Open port `8443` in the firewall to the monitored servers. It carries mutual TLS and must reach
the container directly, never through a reverse proxy that terminates TLS. The web interface
listens on `127.0.0.1:8080`: put an HTTPS reverse proxy in front of it. With Caddy on the same
machine the whole configuration is:

```
tripwatch.example.net {
	reverse_proxy 127.0.0.1:8080
}
```

Without a proxy, `ssh -L 8080:127.0.0.1:8080 your-vps` and http://localhost:8080 also work.
Then sign in with the first user and remove `TRIPWATCH_ADMIN_PASSWORD` from `.env`.

### 2. Sensor

On every server to monitor.

Debian and Ubuntu (the download goes to `/tmp`, which apt's unprivileged `_apt` user can read):

```sh
cd /tmp
curl -fsSLO https://github.com/cpibia/tripwatch/releases/latest/download/tripwatch-sensor_$(dpkg --print-architecture).deb
sudo apt install ./tripwatch-sensor_$(dpkg --print-architecture).deb
```

RHEL, AlmaLinux, Rocky, Fedora and Amazon Linux:

```sh
sudo dnf install https://github.com/cpibia/tripwatch/releases/latest/download/tripwatch-sensor.$(uname -m).rpm
```

Both commands pick the package for the server's architecture (amd64 or arm64). The package
installs `/usr/bin/tripwatch-sensor` and its systemd unit, and creates `/etc/tripwatch`; the
service starts only after enrollment. On other distributions use the static binary from the
release (`tripwatch-sensor_linux_amd64` or `tripwatch-sensor_linux_arm64`) with the unit in [deploy/systemd](deploy/systemd).

Every file of a release is listed in `SHA256SUMS` and has a build provenance attestation, which
proves it was built by this repository's release workflow from the tagged source:

```sh
gh attestation verify tripwatch-sensor_amd64.deb -R cpibia/tripwatch
```

### 3. Enrollment

In the web interface open "Enroll server", choose the server's name and its system, and run
the command it shows on the server. For Debian/Ubuntu or the RHEL family, that single command
also installs the sensor package of the verifier's own release for the server's architecture and
removes the downloaded file, so step 2 can be skipped. With the sensor already installed it is:

```sh
echo 'tw1....' | sudo tripwatch-sensor enroll -token-file - && sudo systemctl enable --now tripwatch-sensor
```

The server shows up in the overview with its first heartbeat within a minute; the first full
snapshot follows shortly.

Instead of the token, the verifier can generate a bundle with the keys already inside, from the
interface or from the command line:

```sh
(umask 077; docker compose exec -T verifier /tripwatch-verifier enroll -host web-01 -out - > web-01.json)
```

Copy the bundle to the server and start the service:

```sh
sudo install -o root -g root -m 600 web-01.json /etc/tripwatch/bundle.json
sudo systemctl enable --now tripwatch-sensor
```

### Kubernetes

On a Kubernetes node, mount the host root into the pod and tell the sensor where it is:

```sh
tripwatch-sensor -root /host
```

### Building from source

Requires Go (the version is in `go.mod`).

```sh
make build   # binaries for this machine in bin/
make dist    # static Linux binaries (amd64, arm64) in dist/
make test    # tests with the race detector
make cover   # tests with the coverage threshold
make lint    # go vet and golangci-lint
```

Releases are built by GoReleaser (`.goreleaser.yaml`) when a `v*` tag is pushed: the workflow in
`.github/workflows/release.yml` publishes binaries, packages, checksums and the verifier image,
each with a build provenance attestation.

To run the verifier from your own checkout instead of the published image:

```sh
cd deploy/verifier
cp .env.example .env
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

## Update and upgrade

### New releases

Every new version is a [GitHub release](https://github.com/cpibia/tripwatch/releases), and
[CHANGELOG.md](CHANGELOG.md) says what changed and whether the verifier, the sensors or both need
updating. To be told when one comes out, open the repository on GitHub, choose **Watch →
Custom → Releases**, and GitHub sends an email for each release; the same list is also a feed
for any RSS reader at `https://github.com/cpibia/tripwatch/releases.atom`.

### Installed versions

To see which version is installed:

```sh
tripwatch-sensor -version                                          # on a monitored server
docker compose exec verifier /tripwatch-verifier -version          # next to the verifier's compose file
```

The verifier also logs its version when it starts, and every sensor sends its version in the
signed event of each start.

Upgrade the verifier first: a newer verifier accepts the envelopes of older sensors, and its
enrollment page then installs the sensor of its own release.

### Upgrading the verifier

`TRIPWATCH_VERSION` in `.env` chooses the image: `latest` by default, or a release number such
as `0.1.4`. Docker never fetches a newer image by itself, so with
`latest` the update happens only when you ask for it:

```sh
docker compose pull && docker compose up -d
```

To decide release by release instead, pin a number in `TRIPWATCH_VERSION` and change it before
running the same two commands. Pinning matters where a platform redeploys for you: one that pulls
images on every deploy moves `latest` forward without being asked.

The state stays in the `data` volume and the sensors keep their chain. On a platform such as
Coolify, change the tag in the service's compose, or with `latest` pull the image, and redeploy.

### Upgrading the sensor

From 0.1.4 the sensor updates itself:

```sh
sudo tripwatch-sensor -update
```

It finds the latest release, downloads the file of the same kind as the installed one (the
`.deb` when dpkg owns the binary, the `.rpm` when rpm does, the static binary otherwise) for the
server's architecture, checks it against the release's `SHA256SUMS` and installs it with dpkg,
rpm or by replacing the binary. A running sensor is restarted and resumes the same chain; if the
latest release is not newer, nothing changes. The checksum comes from the same release, so it
catches a damaged download; to prove where a file was built, use `gh attestation verify`.

Sensors older than 0.1.4 have no `-update`: install the package of the new release the same way
as the first time. Debian and Ubuntu:

```sh
cd /tmp && f=tripwatch-sensor_$(dpkg --print-architecture).deb && curl -fsSLO https://github.com/cpibia/tripwatch/releases/latest/download/$f && sudo apt install ./$f && rm $f
```

RHEL family and Amazon Linux:

```sh
sudo dnf install https://github.com/cpibia/tripwatch/releases/latest/download/tripwatch-sensor.$(uname -m).rpm
```

Check the result with `tripwatch-sensor -version`.

### Removing

`apt remove tripwatch-sensor` or `dnf remove tripwatch-sensor` stops and removes the sensor, and
keeps the bundle in `/etc/tripwatch` and the state in `/var/lib/tripwatch`, so a reinstall
resumes the same chain. The verifier keeps its state in the `data` volume: `docker compose down`
leaves it, `docker compose down -v` deletes it with the CA and every enrollment.

## What the sensor collects

| Collector | What it reports |
|---|---|
| `accounts` | users, UIDs, groups (including members, administrators and group passwords from `/etc/gshadow`) and password state (set, locked, empty); hashes are never collected |
| `ssh` | sshd settings read the way sshd reads them (`Include` followed where it appears, first value wins), `Match` blocks reported in full, every authorized key of every account with fingerprint, comment and options such as `command=` |
| `sudoers` | sudo rules, following `#include`, `@include` and `#includedir` wherever they point, and the other policies that give a user root: polkit rules and `.pkla` files (used by `pkexec` and `systemd-run`), `doas.conf`; owner, mode and ACLs of the policy files and of every directory above them up to `/`, also along links. A file or directory writable by a user other than root is a critical alert: owner, an ACL granting write to a user or group, a writable group with at least one member other than root. polkitd is trusted only on polkit's directories, and only if it is a system account without a shell and with a UID of its own; a group that can write a policy becomes privileged. The full line diff is stored with the alert and shown on its page |
| `scheduled` | system and user crontabs, `cron.daily` and similar scripts, pending `at` jobs |
| `services` | systemd units and override drop-ins, system, transient and per-user, with their `Exec*` commands and activation links; generators; `system.conf` and `user.conf` with their `DefaultEnvironment` |
| `hooks` | `ld.so.preload`, `rc.local`, `profile.d`, PAM, `update-motd.d`, package manager hooks, the shell rc files of every account |
| `processes` | every process with its executable (flagged if deleted from disk or run from memory with `memfd`), hash, working directory, `LD_PRELOAD`, namespaces, the process tracing it with ptrace, and the code it maps from where none is installed (memory-only files, scratch directories, homes and web roots, files deleted outside the system's library directories); command lines with passwords, tokens and credentials redacted; kernel threads (kernel flag) are only counted, processes imitating their names are listed |
| `sockets` | listening sockets, open connections and pending outbound attempts, in every network namespace (containers included), mapped to their process; packet (`AF_PACKET`) and raw sockets with the executable of the process holding them, since backdoors that open no port wait on one for a trigger packet |
| `packages` | system files that no longer match the package database (dpkg, apk, rpm), a fingerprint of the database itself, executables and symlinks no package owns, hidden entries under `/usr` that no package installed (and anything added inside a packaged hidden directory). The rpm database is read directly, Berkeley DB (RHEL/CentOS 7 and 8, Amazon Linux 2) or SQLite (RHEL 9, Amazon Linux 2023, Fedora), never through the host's `rpm`; files rpm itself excludes from verification (`%ghost`, `%verify(not md5)`, languages and documentation not installed) are skipped. Source trees (`/usr/src`, `/usr/local/src`) and language package trees (`node_modules`, `site-packages`, `dist-packages`) are not searched for hidden entries: checkouts and packages ship dot-files there |
| `privileged` | a scan of the whole filesystem (including the world-writable directories in `/run` and `/dev/shm`) for setuid and setgid binaries, files with Linux capabilities, immutable and append-only files; files on a FUSE filesystem mounted by a user other than root are marked with that mount, since that user chooses their owner and mode |
| `kernel` | loaded modules from both of the kernel's lists (`/proc/modules` and `/sys/module`: a module in only one of them is hiding), each with its file in the running kernel's `modules.dep` (a module outside the tree was loaded by hand), taint flags and lockdown mode; processes that exist but are missing from `/proc`'s listing, found by probing every PID the kernel may have handed out (threads told apart by their thread group); eBPF programs held open by processes with their type, pinned BPF objects, dynamic kprobes defined through tracefs |
| `weblog` | web server access and error logs, read incrementally: attack events grouped by rule, IP and path, statistics on IPs and POST targets |
| `apps` | for WordPress, Magento, Drupal and Laravel: administrators in the database, active extensions, scripts stored in settings and content with the domains they load from or send to, development settings left on in production |
| `web` | inventory of sites and applications, and for each application: hash tree of the code, scripts in upload directories, polyglot images, webshell signatures, hidden files, scripts the web server actually executes |

The sensor also detects the environment it runs in (host, container, Kubernetes, Fargate) and the
container runtimes present, and reports the machine's system: distribution, kernel, architecture,
hostname, boot time, CPUs, memory, the addresses of its interfaces and its own version.

## Real-time events

Between two snapshots the sensor watches the places an intruder uses to get in or stay, and sends
what changes there within two seconds, in signed event envelopes of the same chain:

- **Files**, with inotify: the account databases, sudoers, polkit and doas, the SSH server
  configuration and every account's `authorized_keys`, cron and `at`, systemd units and
  generators, `ld.so.preload`, `profile.d`, PAM, `rc.local` and the shell rc files of every
  account, and the upload directories of the web applications found by the last snapshot. Each
  event carries the size, SHA-256, owner and mode of the file after the change, read without
  following links.
- **Processes**, with the kernel's process connector: only the starts that mean something, not
  the thousands a busy server makes. A shell, an interpreter or a network tool started by the web
  server's user; a program or a script run from `/tmp`, `/dev/shm`, a home or a web root; a
  program whose file was deleted after it started; root gained through a set-user-ID program
  outside the system's binary directories.

The verifier keeps the events for seven days (at most 20,000 a server in 24 hours for uploads
and process starts and as many for system paths, so a flood cannot push out the first ones, nor
noise in the uploads root's changes) and judges them at once. The web server's user starting a shell,
root gained through an unknown set-user-ID program, a change to who may become root or to library
preloading are critical. A script or an `.htaccess` landing in an upload directory, new SSH keys,
services, scheduled tasks and start-up scripts are high. What a snapshot an hour later could not
show is critical too: a script that appears in the uploads and is gone within 15 minutes, an SSH
key file written and removed, or changed and put back. While a package manager runs (a process
of root holds the lock of dpkg, rpm or apk: a process merely named `dpkg` does not count),
changes to services, scheduled tasks and start-up scripts are one severity lower; changes to who
may become root, to accounts, to SSH keys and to library preloading never are, nor are process
starts and uploads. The server's page lists its latest events and says whether the watchers run.

The watchers are bounded against the users they guard against: files are hashed only up to 1 MB
and 16 MB a second (root's files with a budget of their own, which other users cannot spend),
larger ones are reported with their metadata; when the queue is full, noise
in the uploads is dropped before any change to a system path, and losing one of those is an
alert of its own; directories left unwatched by the depth or count limits are listed in the
snapshot; and what is queued when the sensor stops is sent before its stop event.

The watchers need Linux and, for process events, `CAP_NET_ADMIN` in the host's network namespace,
which the systemd unit grants. The sensor needs it only to subscribe: it gives it up right after,
on every thread, and a snapshot says so if it could not. Where either is missing the sensor goes on with snapshots, and each
snapshot tells the verifier which watchers are off and why. To see what they report on a machine,
without a verifier:

```sh
sudo tripwatch-sensor -watch-only
```

## Web stack

The sensor reads the configuration of **nginx**, **Apache httpd** (Debian and Red Hat layouts) and
**Caddy**: virtual hosts, document roots, logs, upstreams and, for nginx, the `location` blocks
with the same selection order nginx uses. So it knows which scripts are reachable from the
internet and which are not: an admin tool forgotten among the executable entry points is flagged
as reachable, a script uploaded to a directory protected by `deny all` is not.

Applications are recognized by their fingerprints in `/var/www`, `/srv`, `/opt`, `/home`, Docker
volumes and site document roots. Profiles cover the main CMSs and frameworks (WordPress, Drupal 7
and 8+, Magento, Laravel, Symfony, Django, Rails), Java, Rust, Go, Node and Python applications,
generic PHP and static sites; for the main frameworks the installed version is read too. Adding a
stack means adding a profile: markers to look for, public directory, upload and data directories,
files to read the version from.

For each application the `web` collector produces:

- a **hash tree** (Merkle) of the code, with directory hashes down to the second level: a line
  changed in a dependency changes the hash of its directory and the overall one, while uploads,
  cache and logs stay out of it;
- **scripts in upload directories** (`.php`, `.phtml`, `.phar`, `.jsp`, `.aspx`, double
  extensions such as `shell.php.png`) and **code inside files that are not scripts**, such as the
  serialized sessions used by deserialization exploits;
- **polyglot images**: GIF, JPEG or PNG with code after the header or at the end;
- **webshell signatures**: `eval` of decoded payloads, commands run with request input, droppers
  that write code through library classes and more, matched after stripping comments from the
  source; very long encoded blobs are reported separately as a weak indicator;
- **hidden files** among scripts and in data directories, except the tool configurations and
  test fixtures that libraries ship on purpose (signatures are still searched in those);
- per-directory configuration files (`.htaccess`, `.user.ini`, `web.config`) with their hash,
  and a finding when they sit in an upload directory, naming the directives that make files run
  as scripts;
- applications nested in an upload or data directory, and suspicious symlinks. An upload
  directory that is itself a link to a directory inside the application or its deploy directory
  (`releases/5/uploads -> ../../shared/uploads`) is the usual deploy layout: it is followed and
  scanned, not reported.

`reachable` tells whether a file would be executed according to the configuration on disk. It is
a hint, never a reason to lower a finding's severity: whoever controls the configuration can
change it. Configurations modified after the web server started are flagged, because the running
one may differ.

The collector has been run on real applications of different stacks, up to more than 170,000
files per application. The remaining false positives are library files that really contain those
patterns (for example code analysis tools that search for `preg_replace` with `/e`): accept them
once in the verifier (see [Interface](#interface)) and they are not raised again while they stay
identical.

## Applications and databases

The `apps` collector reads the configuration of recognized applications (`wp-config.php`,
`app/etc/env.php`, `settings.php` and `settings.local.php`, `.env`) and, if the database is MySQL
or MariaDB, queries it with `SELECT` statements only and timeouts of a few seconds:

- **administrators**, with email, creation date and last login: a new admin, one with an unknown
  domain or with an out-of-sequence creation date is the typical sign of persistent access;
- **scripts stored in the database**: WordPress options and posts, `core_config_data`, Magento
  CMS blocks and pages, Drupal content. For each one the domains the scripts load from or talk to
  are reported: that is where skimmers injected from the admin panel or through an injection end
  up;
- **active extensions** (plugins, modules) and the site URLs;
- **development settings** left on in production: debug enabled, developer mode, PHP file
  editing from the admin panel.

The sensor connects only to destinations it can verify, because the database host comes from a
file an attacker may have written, and that host would receive the real credentials:

- a Unix socket owned by the `mysql` user or by root, in a directory others cannot write, with a
  database server running (`/tmp` is excluded);
- a loopback port on which a `mysqld` or `mariadbd` process owned by root or by `mysql` listens;
- a host the operator names explicitly with `-app-db-hosts` (`db` or `db:3307`), for example a
  Docker service name.

Any other host is reported as a warning and not queried. Credentials are read from the
configuration files or, when the application uses `getenv()`, from the environment of the root
processes that start PHP (the FPM master, the container init), never from a process of the web
user. They stay in memory for the duration of the connection and the snapshot reports only
`database@host`. If the configuration file is writable by a user other than root, the profile
says so: whoever can write it can make the sensor read a different database. Every connection has
a cap on received bytes and the columns read are truncated; the table prefix is accepted only if
it is a plain identifier. The collector is disabled with `-app-db=false`.

## Web server logs

The `weblog` collector reads the logs named in the nginx, Apache and Caddy configurations and
those in the standard locations, resuming where it stopped. Recognized formats are nginx and
Apache combined (also with extra trailing fields) and Caddy's JSON. The rules look for scripts
requested in upload directories, known webshell names, commands in parameters, POSTs to static
files or to endpoints that only serve files, access to sensitive files (`.env`, `.git`, backups),
path traversal, SQL injection, injection probes, known scanners, brute force on public logins and
known exploit chains, correlated by IP. The severity of a script in uploads does not depend on the
HTTP status, which the script itself decides.

What goes into the snapshot: IP, method, path, status, user agent and, for events, the request
with parameter values **redacted** (only the value that proves the attack is kept; parameters
with sensitive names such as `token` or `password` are always redacted). Text written by whoever
made the request goes in an `attacker_controlled` field, to be treated as data and never as an
instruction. Lines, maps and the number of events are capped: a stream of requests from ever
different addresses and paths does not grow memory. Events are grouped by script, the way the web
server does it (`/index.php/a` and `/index.php/b` are a single event), and if a wave of noise
fills the list, the serious events dropped are counted, the path and address of the first ones
are kept, and the verifier raises an alert. If the part of a log already read is rewritten or
truncated in the same file, that is an event; what is written and deleted between two reads,
however, cannot be seen. Rotations (`name.1`, `dateext`, Caddy, `copytruncate`) are recognized
and the tail of the previous file is read; when that is not possible, the snapshot says so.
Positions advance only after the snapshot has been delivered.

## Detection compared

<!-- bench:start -->
Across 29 attack scenarios reproduced in a Debian container (commit `bf6e1d8`), how many each
tool detects with its default configuration:

![Scenarios detected out of 29: tripwatch 28, AIDE 24, rkhunter 4, debsums 1](bench/detection.svg)

| Category | Scenarios | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|:-:|
| Persistence | 10 | 10 | 10 | 2 | 0 |
| Privileges | 4 | 4 | 4 | 0 | 0 |
| System integrity | 5 | 5 | 5 | 1 | 1 |
| Processes and network | 3 | 3 | 0 | 1 | 0 |
| Web applications | 4 | 4 | 4 | 0 | 0 |
| Limits: attacks between two checks, and traps | 3 | 2 | 1 | 0 | 0 |
| **Total** | **29** | **28** | **24** | **4** | **1** |

Detects means the data about the attack appears in the output of the tool; for tripwatch the
judgement stays with the verifier: its real-time rules run on what the watchers of the sensor saw while the
scenario ran. The scenarios in the "Limits" category (a dropper or an SSH key that appear and disappear
between two checks) are beyond any tool that only compares states; for them tripwatch relies on its
real-time watchers, and the table says which ones they catch.
Method, results per scenario, versions and cost in [bench/RESULTS.md](bench/RESULTS.md).
<!-- bench:end -->

Where AIDE and tripwatch both see a new file, AIDE only says the file appeared or changed;
tripwatch also says what it is: a script in the upload directory with a webshell signature, an
image carrying PHP code, an `.htaccess` that changes the file handler, obfuscated code injected
into an application file. The cost of a full check (time and memory of each tool) is in
[bench/RESULTS.md](bench/RESULTS.md).

## Trust model

An attacker with root on a monitored server can stop its sensor or make it lie. tripwatch does
not pretend otherwise, but aims to make both visible. Already today:

- messages are signed and chained: a message lost, replayed or forged with a different key is
  detected by the verifier;
- the sensor reads files so that the web server user can neither block it nor exhaust its memory:
  every open is non-blocking and checked on the descriptor (FIFOs and devices are refused), reads
  are capped, huge files are read only at the head and the tail, every collector has a timeout
  and, on Linux, symlinks are resolved inside the observed root;
- the heartbeat reveals a stopped sensor within minutes, and a sensor that keeps sending
  heartbeats but no more snapshots raises an alert of its own; every sensor start arrives as a
  signed event and every gap between two heartbeats over 100 seconds becomes an alert, so even a
  stop or a suspension shorter than the silence threshold leaves a trace; a sensor that is
  stopped says so in a last signed event, and one removed with its package (`apt remove`,
  `dnf remove`) raises a high alert at once instead of only falling silent; each start is judged
  against how the previous run ended, from what the sensor signed as it stopped: only a stop made
  while systemd was shutting the system down, followed by a new boot, is one low "Server was off"
  event (a server switched off every night raises no more), and only a stop for an update of the
  package, followed by a new version, is a low "Sensor updated". A service stopped on a running
  system stays critical while silent and high when it comes back, even after a later reboot, so
  stopping the sensor, working and then rebooting is not quiet; so do a crash or a killed sensor
  before a reboot, and another version without an update. The silence after a signed shutdown is
  medium for a day, then high;
- critical and high alerts do not close by themselves when the condition goes away: a
  compromised server could clean up and silence its own alerts, so a person closes them.

- [real-time events](#real-time-events) leave the server within two seconds: a key used and
  removed, a webshell dropped and deleted, a shell started by the web server are on the verifier
  before the attacker can turn to the sensor.

Coming next:

- process and file events from eBPF on recent kernels, which also see what the process connector
  cannot (connections, module loads, writes to files outside the watched directories);
- checks that do not run on the server (pages fetched from outside, cloud provider APIs, canary
  tokens, disk snapshots verified offline), which cannot be silenced from there.

An attacker with root can copy the signing key and continue the chain with credible data: the
external checks and, later, a hardware-bound key are the answer to that.

Most web compromises spend weeks or months as the web server user before reaching root. In that
phase the attacker has no permission to stop the sensor or change its files, and the files they
can create are not enough to block it.

The full design is in [docs/architecture.md](docs/architecture.md).

## Known limits

- Container storage (`/var/lib/docker` and similar) is not examined yet: it will come with the
  container collector, which will compare running containers with their images.
- Real-time events cover the watched places and the process starts listed in
  [Real-time events](#real-time-events): a file that appears and disappears elsewhere between two
  snapshots is not seen. inotify has a per-user watch limit (`fs.inotify.max_user_watches`): when
  it is reached, the directories not watched are reported. A process that ends before the sensor
  reads it from `/proc` is not described, and a flood of process starts is inspected up to 200 a
  second, the rest counted and reported.
- The host's package database is the reference: with root an attacker can update a checksum to
  cover a replaced binary. Its fingerprint changes and the verifier sees that between two
  snapshots; comparing with the repositories' signed metadata is still an open choice.
- A FUSE filesystem mounted by a user hides the directory it is mounted on, and a remount with
  `suid` done by root does not change how its files are marked.
- Outside Linux the sensor is for development only: symlink confinement relies on Linux
  interfaces.
- With one heartbeat a minute, a sensor suspended for less than 100 seconds cannot be told apart
  from network delay and raises no alert; longer pauses do, even if the heartbeats resume.
- Whoever keeps producing alerts without being root, the web server user with hidden files or an
  anonymous visitor with suspicious requests in the logs, can cause up to 24 snapshots a day per
  alert type and severity to be kept (about 40 a day in all, in the worst case): that server's
  4 GB quota fills in about a year and a half instead of never, and a real file of the same
  severity arriving on a day already saturated with decoys is kept for only 48 hours (medium
  severity decoys do not touch the budget of critical ones). What only root can cause (UID 0
  accounts, root's SSH keys and crontab, setuid root files or setgid files of a system group the
  owner does not belong to, system persistence, packages) is instead always kept as evidence, and
  other users' keys, crontabs, units and environment cannot take its place.
- An attack very expensive for the verifier (more than a hundred thousand login attempts in an
  hour, each with its own password check) can make a new non-existent email answer more slowly
  than a user's, revealing which addresses exist.
- Someone signing in to the console from a browser never used before, while someone else keeps
  trying passwords on the same email, waits in line with those attempts and may not get in while
  the attack lasts. From browsers already used, sign-in is never slowed down; for the others there
  is the one-time link described below.

## Verifier

The verifier runs on a dedicated machine, outside the monitored servers, as a `docker-compose`
stack. It exposes two ports:

- `8443`, the sensors' ingest: TLS 1.3 with a mandatory client certificate, signed by the
  verifier's private CA. It must be reachable from the monitored servers.
- `8080`, the web interface over HTTP, published on `127.0.0.1` only: expose it through an HTTPS
  reverse proxy (nginx, Caddy, Traefik) or reach it with an SSH tunnel.

To install it, see [Installation](#1-verifier).

On first start the verifier creates the CA, the server certificate for the names in
`TRIPWATCH_HOSTNAMES` and the first user from `TRIPWATCH_ADMIN_EMAIL` and
`TRIPWATCH_ADMIN_PASSWORD` (at least 12 characters; after the first sign-in the password can be
removed from the file). All state (SQLite database, CA, baselines) lives in the `data` volume:
include it in backups, because losing it means enrolling every server again. The container runs
without root, with a read-only filesystem and no capabilities.

Disk use grows with the number of servers, not with time. The verifier keeps every snapshot of
the last 48 hours; then, up to 30 days, the last one of each day and those that show a change
together with the previous one; the first one of each server forever. With compressed snapshots
of a few hundred KB that comes to about 40 MB per server, so 50 servers fit in a couple of GB;
heartbeats and alerts weigh little. A server that exceeds 1 GB of snapshots in a day, or 4 GB
kept in all, stays alive for the verifier, but the snapshots over quota are not kept and an alert
appears; likewise a server cannot keep more than 2000 alerts open.

More users or a new password:

```sh
docker compose exec verifier /tripwatch-verifier user -email colleague@example.net
```

To sign in from a new browser when normal sign-in is blocked by someone else's attempts, a
one-time link valid for ten minutes, which also makes that browser known:

```sh
docker compose exec verifier /tripwatch-verifier login-link -email ops@example.net
```

The link opens a page with a button, and the session starts only when it is pressed: chat
previews and mail scanners that open the link do not consume it. A password change voids the
links not yet used. After a leaked password, the browsers it was used from are forgotten with:

```sh
docker compose exec verifier /tripwatch-verifier revoke-browsers -email ops@example.net
```

The command does not close sessions already open: for a lost or stolen laptop a password change
is needed too, which closes them all.

### Interface

- **Overview.** An operations dashboard. At the top, a figure for each severity of open alerts
  and for silent sensors, with what arrived in the last 24 hours, the age of the oldest and the
  last 7 days' trend. Then the alerts raised over the last 24 hours or 7 days, stacked by
  severity; the servers as cells with their worst alert, last heartbeat and snapshot; the open
  alerts grouped by rule across servers, without buttons in the rows; the rules that raised most
  alerts in the last 7 days, the unresolved alerts by server, and the sources and targets of the
  attacks seen in the web server logs. Every figure comes from what the verifier holds. Every severity has a shape as well as a color (diamond for silent, triangle critical,
  square high, circle medium, hollow circle low), and a silent server is a present mark with a
  dashed row, not a dimmed row.
- **Servers.** The fleet: every server with its system and kernel, the sensor's version (flagged
  "update available" when it is older than the verifier, with the command to run), its
  addresses, the web applications found on it, the last heartbeat and snapshot and the number
  of alerts; revoked servers listed apart.
- **Server.** State, the system as the sensor read it (with the package manager and count, the
  listening ports, the web applications and whether the real-time watchers run), every alert,
  the latest real-time events, the silences of the last 7 days with
  their duration, the last snapshots received, revocation.
- **Alerts.** To handle, acknowledged, resolved. At the side (above the list on smaller screens)
  the alert to look at first, chosen by severity and then by kind (a silent sensor, then code
  planted in a web application, then the rest), with its actions; clicking another alert shows
  that one in the panel, with a link to its detail. Every alert can be acknowledged and resolved;
  the detail shows the text collected from the server as data, without interpreting it. Alerts
  of the same rule, server and severity (one per file, request or process) are one row that opens
  onto them, each row showing the file or item that tells it apart, with actions that
  acknowledge or resolve the whole group; resolving or accepting a group of critical or high
  alerts asks once more with their number. An open group stays open across the automatic
  refresh. In long lists the actions appear on the row being pointed at. Resolving closes an alert, but a condition still present comes
  back with the next snapshot. **Accept as legitimate** (on an alert's page, or for a whole group) declares it legitimate,
  such as a file a library ships: it is not raised again while its evidence (for a file, its size
  and SHA-256) stays the same, and a changed file or a new one is an alert again. The server's
  page lists what was accepted, by whom and when, and puts any of it back under watch. Silences,
  broken chains, sensor events and the verifier's own alerts cannot be accepted. Every alert
  page also has **Copy for an AI assistant**, which copies the alert as Markdown to paste into
  an AI chat, with the collected detail marked as data.
- **Enroll server.** Generates the one-time token with the command to run on the server, or the
  bundle with the keys to download once; the verifier keeps neither.

Dark theme by default, light or following the system from the menu; refreshes by itself every
minute and works on a phone too. The mark in the menu, a tripwire cut in the middle, and the
browser tab icon turn red while a critical alert is open; a verifier without email shows it as a
warning in the menu. Fonts (IBM Plex) are embedded in the binary and served by the verifier. Pages run no inline scripts or styles (strict Content Security
Policy), forms are protected by CSRF tokens, and sign-in attempts for the same email address go
through one at a time, with a delay that grows after five failures up to 15 seconds, whatever
address they come from: guessing the password becomes very slow even in parallel. A browser that
has already signed in has a lane of its own, which no attack slows down, so the user is never
locked out.

### Email

With `TRIPWATCH_SMTP_HOST` set, critical and high alerts arrive by email, grouped into one message
per round, with a link to the detail. If sending fails, the interface shows it as a verifier
alert.

## Sensor

Enrollment is described in [Installation](#3-enrollment). With a token, the sensor generates its
own TLS key and signing key, checks that the verifier is the right one by comparing its CA with
the fingerprint in the token, and only then sends the secret and the public keys; private keys never leave the server. The token is valid for one hour and once only,
and the verifier keeps only its hash. The token goes through standard input because any user on
the server can read a process's arguments; every enrollment raises an alert, and a token presented
again after use raises a critical one, because it means someone has a copy. On certificate
renewal, too, the new key is born on the server.

The sensor refuses a bundle not owned by its user, readable by other users or with a verifier
address that is not `https`. The client certificate lasts two years and the sensor renews it by
itself in the last two months, without a restart and without touching the bundle. State kept
between runs (position in the chain, envelope awaiting acknowledgement, log positions) lives in
`-state-dir` (default `/var/lib/tripwatch`); every envelope is saved before being sent and resent
identical if the acknowledgement is lost.

Without `-bundle` the sensor prints a JSON snapshot and exits, useful to see what it collects
on any Linux machine:

```sh
sudo tripwatch-sensor > snapshot.json
```

With `-watch-only` it prints the real-time event batches as JSON lines until interrupted.

A systemd unit with security restrictions is in [deploy/systemd](deploy/systemd).

## Roadmap

1. Real-time events from eBPF on kernels 5.8 and later, with the current watchers as the
   fallback.
2. Installation without a toolchain: signed `.deb`, `.rpm` and `.apk` packages and APT/YUM
   repositories (one-time token enrollment already exists), image and Helm chart for the
   DaemonSet; the verifier compares the running binary with the published release.
3. Signed deploy manifests produced by the build and checked against the lockfile.
4. Containers: differences of running containers from their image, privileged containers.
5. Kubernetes and AWS: DaemonSet, audit logs, CloudTrail, VPC Flow Logs.
6. External checks and canary tokens.
7. rpm ndb databases (SUSE).
8. PostgreSQL databases for the application profiles (Django, Rails, Drupal on PostgreSQL).

## Status

Early development, usable end to end. Implemented and tested: the envelope protocol, environment
and web stack discovery, the system, web, log and application collectors, the sensor as a
service with real-time events for critical paths and process starts, the verifier with rules,
alerts, email and web interface. The next step is eBPF events on recent kernels.

## License

[Apache License 2.0](LICENSE). The embedded IBM Plex fonts are under the SIL Open Font License
1.1, included as [internal/verifier/ui/static/fonts/OFL.txt](internal/verifier/ui/static/fonts/OFL.txt).
