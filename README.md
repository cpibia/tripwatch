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

Before an upgrade, a backup taken while the verifier runs, with no stop:

```sh
docker compose exec verifier /tripwatch-verifier backup
```

It writes a consistent, compacted copy of the database and the certificate authority (its
private key included) to a new directory under `/data/backups`, readable by its owner only, and
prints its path; `-out` chooses another. To roll back, stop the verifier and put `tripwatch.db`
and `pki/` back in the data volume. The copy lives in the same volume: for a disaster, move it
off the machine, encrypted.

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

From 0.1.17 every sensor can also be updated from the verifier: when sensors are older than it,
the servers page offers to update them all to the verifier's own release. The verifier reads the
release's `SHA256SUMS` once, signs the hashes of the sensor's files with its CA key, which every
sensor holds since enrollment, and hands the order to each sensor in its answers. A sensor checks
the signature and the version (never older than its own), then installs in a transient systemd
unit, outside its own service, the file only if it matches the signed hash: a release changed
after the order installs nothing. Revoking a server likewise tells its sensor, by an order naming
that host and signed the same way, to remove itself: the package is purged (or the service, its
unit and the binary removed), and `/etc/tripwatch` and `/var/lib/tripwatch` are deleted.
Whoever controls the verifier's console can therefore update every sensor to a published release,
or remove a sensor by revoking its server; neither reaches a host whose sensor runs without
systemd, nor installs anything but the files of a release as they were when the order was given.

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
| `scheduled` | system and user crontabs, `cron.daily` and similar scripts, pending `at` jobs. A new cron line is a high alert, critical when it never runs on schedule (a date such as the 31st of February, where CronRAT hides its code), downloads and runs, decodes a base64 payload or starts a process under another name |
| `services` | systemd units and override drop-ins, system, transient and per-user, with their `Exec*` commands and activation links; generators; `system.conf` and `user.conf` with their `DefaultEnvironment` |
| `hooks` | `ld.so.preload`, the loader's search path (`ld.so.conf` and `ld.so.conf.d`, and the directories `ld.so.cache` actually searches: one no configuration names, put there by `ldconfig <dir>`, is a high alert; the system's own directories are `/lib`, `/usr/lib` and the one holding each architecture's libc, not any directory of that shape, and a cache too large to read whole is a high alert too), `rc.local`, `profile.d`, PAM, `update-motd.d`, `bash_completion.d`, package manager hooks, SSH login scripts (`/etc/ssh/sshrc` and every account's `~/.ssh/rc`), the scripts run when a network interface changes state (ifupdown, NetworkManager, networkd-dispatcher, dhclient, ppp), the shell rc files of every account |
| `processes` | every process with its executable (flagged if deleted from disk or run from memory with `memfd`), hash, working directory, `LD_PRELOAD`, namespaces, the process tracing it with ptrace, and the code it maps from where none is installed (memory-only files, scratch directories, homes and web roots, files deleted outside the system's library directories); command lines with passwords, tokens and credentials redacted; kernel threads (kernel flag) are only counted, with the distinct names they run under on the host; processes imitating a kernel thread (a usual name such as `kworker/0:1`, or one of the host's own threads such as `kauditd`, by name or as `[name]` on the command line) are listed and raise a critical alert. At most 10,000 processes and 4 MB of command lines: past that, the processes the rules judge (unusual or deleted executables, injected code, ptrace, `LD_PRELOAD`) and root's come first, the other command lines are cut to 256 bytes, and the processes left out are counted by owner |
| `sockets` | listening sockets, open connections and pending outbound attempts, in every network namespace (containers included), mapped to their process; packet (`AF_PACKET`) and raw sockets with the executable of the process holding them, since backdoors that open no port wait on one for a trigger packet. At most 20,000 sockets: past that, raw and packet sockets, root's and listeners come first, and the others left out are counted by owner |
| `packages` | system files that no longer match the package database (dpkg, apk, rpm), a fingerprint of the database itself, executables and symlinks no package owns, hidden entries under `/usr` that no package installed (and anything added inside a packaged hidden directory). The rpm database is read directly, Berkeley DB (RHEL/CentOS 7 and 8, Amazon Linux 2) or SQLite (RHEL 9, Amazon Linux 2023, Fedora), never through the host's `rpm`; files rpm itself excludes from verification (`%ghost`, `%verify(not md5)`, languages and documentation not installed) are skipped. Source trees (`/usr/src`, `/usr/local/src`) and language package trees (`node_modules`, `site-packages`, `dist-packages`) are not searched for hidden entries: checkouts and packages ship dot-files there |
| `privileged` | a scan of the whole filesystem (including the world-writable directories in `/run` and `/dev/shm`) for setuid and setgid binaries, files with Linux capabilities, immutable and append-only files; files on a FUSE filesystem mounted by a user other than root are marked with that mount, since that user chooses their owner and mode; network filesystems (NFS, SMB, WebDAV, S3 and the like) are not walked, and one mounted without `nosuid` is listed in the issues |
| `kernel` | loaded modules from both of the kernel's lists (`/proc/modules` and `/sys/module`: a module in only one of them is hiding), each with its file in the running kernel's `modules.dep` (a module outside the tree was loaded by hand), taint flags and lockdown mode; processes that exist but are missing from `/proc`'s listing, found by probing every PID the kernel may have handed out, ten seconds a run, each run going on from where the previous one stopped (threads told apart by their thread group); eBPF programs held open by processes with their type, pinned BPF objects, dynamic kprobes defined through tracefs |
| `containers` | Docker containers from the daemon's state directory (its data root read from `daemon.json`), and those of containerd (Kubernetes included), Podman and CRI-O from their OCI bundles: name, image, whether running, and what gives each power over the host: privileged mode, added capabilities, the host's PID, network, IPC or user namespace, unconfined security profiles, devices, and the host directories, runtime sockets and sockets of other daemons acting as root (system D-Bus, systemd, snapd, libvirt, LXD, BuildKit) mounted in it; never the environment, which holds the application's secrets. A container that appears with one of the powers that amount to root on the host (privileged, an administrative capability, the host's processes, a runtime socket or a directory holding one, the host's root or system directories, a raw disk or a device cgroup rule granting one) raises a high alert, and so does a list of mounts, devices or capabilities longer than the 64 entries read (what gives power is kept first). Mounts are judged by where they lead: a Docker volume whose local driver binds a host path is that path, and a link is followed inside the observed root; for a running container (Docker, containerd) every entry of its process's mount table is also matched to the host paths of the same filesystem, which a link swapped around the start, a link in the image or a chroot cannot hide, and adds powers without removing any (one the configuration does not list is judged the same way, the runtime's own layers, volumes and state files aside); a mount table that cannot be read, or that lacks a host directory or file the configuration binds, is itself a power; and below the system directories (`/etc`, `/root`, `/usr`, `/var/lib/docker`, ...) any writable path counts, and any readable one where secrets live (`/etc/shadow`, `/etc/ssh`, `/root`, `/proc`); time zone files, `/etc/hosts` and `resolv.conf` do not; a redeploy of one already there (same name, image and powers) does not |
| `weblog` | web server access and error logs, read incrementally: attack events grouped by rule, IP and path, statistics on IPs and POST targets |
| `apps` | for WordPress, Magento, Drupal and Laravel: administrators in the database, active extensions, scripts stored in settings and content with the domains they load from or send to, triggers, routines and events of the schema, Magento integrations, admin tokens, layout updates and email templates, development settings left on in production |
| `web` | inventory of sites and applications, and for each application: hash tree of the code, scripts in upload directories, polyglot images, webshell signatures, hidden files, scripts the web server actually executes; a network filesystem mounted inside an application is left out and listed in the issues |

The sensor also detects the environment it runs in (host, container, Kubernetes, Fargate) and the
container runtimes present, and reports the machine's system: distribution, kernel, architecture,
hostname, boot time, CPUs, memory, the addresses of its interfaces (not those of container
bridges and virtual links, the same on every host) and its own version.

## Real-time events

Between two snapshots the sensor watches the places an intruder uses to get in or stay, and sends
what changes there within two seconds, in signed event envelopes of the same chain:

- **Files**, with inotify: the account databases, sudoers, polkit and doas, the SSH server
  configuration and every account's `authorized_keys`, cron and `at`, systemd units and
  generators, `ld.so.preload` and the loader's search path, `profile.d`, `bash_completion.d`,
  PAM, `rc.local`, the SSH login scripts, the network interface hooks and the shell rc files of
  every account, the upload directories of the web applications found by the last snapshot, and the
  scratch directories (`/tmp`, `/var/tmp`, `/dev/shm`), where only executable files count: a
  dropper written, run and deleted there lives too briefly for its process to be read. Each
  event carries the size, SHA-256, owner and mode of the file after the change, read without
  following links.
- **Processes**, with the kernel's process connector: only the starts that mean something, not
  the thousands a busy server makes. A shell, an interpreter or a network tool started by the web
  server's user; a program or a script run from `/tmp`, `/dev/shm`, a home or a web root; a
  program whose file was deleted after it started; root gained through a set-user-ID program
  outside the system's binary directories. The scripts a package manager writes to `/tmp` or
  `/var/tmp` and runs during an installation are left out only when root runs a root-owned file
  named the way the package manager names it, started by the package manager's own executable:
  `<package>.config.XXXXXX` from the system's perl running `/usr/sbin/dpkg-preconfigure`,
  `rpm-tmp.XXXXXX` from rpm, dnf5, microdnf, PackageKit or the system's Python running
  dnf or yum. Some shells of the web server's user are its own work: `sh -c` running sendmail
  with options only (PHP's `mail()`); ClamAV scanning one uploaded file, with options only
  (the upload plugins of CMSs); an error reporter reading the project's git root (Flare
  and Ignition, `echo $(git rev-parse --show-toplevel)`, matched whole); and a framework
  command (`php artisan ...`, `bin/console`, `bin/magento`) whose parent is that framework's
  scheduler or worker, not the PHP pool, with nothing a shell interprets but the redirection to
  `/dev/null` (`exec` in front and Laravel's background form included, BusyBox's `sh` too).
  What a container runtime starts (runc, crun, containerd's shim or conmon, from the system's
  directories and as root), directly or through shells, is a health check or a `docker exec`,
  never a request to the web server inside the container; runc caught exiting as the command
  starts counts when its own parent is such a runtime. Each command is an alert of its own, one
  that can be accepted; a command fed a here-document (a script piped to `ssh host sh -s`, as
  deploy and server management tools do) is keyed on what comes before the `<<`, so a new
  script at every run does not make a new alert. A start identical to one reported in the last
  hour is counted instead of sent again, so a job that runs every minute does not fill the budget.
- **Containers**, by listing the state of Docker, containerd, Podman and CRI-O every second: a
  container that appears with power over the host (privileged mode, an administrative
  capability, the host's processes, the host's root, a system directory or a runtime socket
  mounted, a raw disk) is
  reported at once, and so is its removal, so one started to escape and removed seconds later is
  seen although no snapshot ever shows it. Containers there before the sensor started, those
  without such a power and redeploys of one seen within the hour (same name, image, digest and
  powers) are left to the snapshots; the same name, tag and powers on another image digest is
  reported as a medium alert naming both digests, and accepting a container's alert covers only
  its digest. containerd and Podman leave no image digest in their bundles: for them another
  image under the same tag is not told apart, and the alert says so.

The verifier keeps the events for seven days, unless configured otherwise (at most 20,000 a server in 24 hours for uploads
and process starts, as many for the homes and crontabs of accounts other than root, 2,000 of
them for each account, and as many for root's system paths, so a flood cannot push out the first
ones, nor noise in the uploads or in a user's home root's changes) and judges them at once. The web server's user starting a shell
(not one cron starts, where that account also runs scheduled jobs: a crontab it planted is
reported by the schedule rules), root gained through an unknown set-user-ID program, a change to who may become root or to library
preloading are critical. A script or an `.htaccess` landing in an upload directory, new SSH keys,
services, scheduled tasks and start-up scripts are high. What a snapshot an hour later could not
show is critical too: a script that appears in the uploads and is gone within 15 minutes, an SSH
key file written and removed, or changed and put back, a loader configuration file written and
removed. While a package manager runs (a process
of root holds the lock of dpkg, rpm or apk: a process merely named `dpkg` does not count),
changes to services, scheduled tasks and start-up scripts are one severity lower; changes to who
may become root, to accounts, to SSH keys and to library preloading never are, nor are process
starts and uploads. The server's page lists its latest events and says whether the watchers run.

The snapshots back the watchers up: a start-up, login, network or loader hook added or changed
since the previous snapshot is an alert (high for system files, medium in a home) unless a
real-time event already reported that content, so a change made while the sensor was stopped or
in a place left unwatched is still seen. A file collected for the first time but changed (by its
inode change time, which cannot be dated back) before the previous snapshot is not new; if
packages were installed, upgraded or removed in the same interval the alert is low, except for a
new file that dpkg's file lists, where the system has them, name in no package. A home's
files are described up to 64 per pattern, the system's up to 1,024.

The watchers are bounded against the users they guard against: files are hashed only up to 1 MB
and 16 MB a second (root's files with a budget of their own, which other users cannot spend),
larger ones are reported with their metadata; when the queue is full, noise
in the uploads is dropped before any change to a system path, and losing one of those is an
alert of its own; in the temporary directories each account has its own share of events a
second, taken before the common one, and a program within its owner's share spends none of the
common one, so another account's junk cannot hide it; events let go over these budgets are a
medium alert of their own, apart from events lost by a sensor that fell behind; directories left unwatched by the depth or count limits are listed in the
snapshot; and what is queued when the sensor stops is sent before its stop event. A watch
follows the inode, not the path, so every few seconds the sensor checks that each watched root
is still the directory at its path: one moved away, replaced under its name (an ancestor moved
aside and recreated) or back after a while is reported and watched again within seconds.

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

Web servers running in containers (Docker, containerd) are read the same way, from the
container's own filesystem as its server sees it (`/proc/<pid>/root`), and every path in their
configuration is translated to where it lies on the host through the container's mounts: a host
serving each site from its own nginx container gets each site with its domain, its code and its
logs on the host, and the name of the container; one that answers any name takes the domain of
the proxy that sends it requests through a port the container publishes. What only the image holds (its default page) is
not on the host's disk and is left out.

Applications are recognized by their fingerprints in `/var/www`, `/srv`, `/opt`, `/home`, Docker
volumes and site document roots. Profiles cover the main CMSs and frameworks (WordPress, Drupal 7
and 8+, Magento, Laravel, Symfony, Django, Rails), Java, Rust, Go, Node and Python applications,
generic PHP and static sites. An application no profile describes says where it writes through
its permissions: a directory of its root anyone may write to is an upload directory, one owned by
another account than the root's (the web server's, as a rule) holds its data. For the main frameworks the installed version is read too, from
`composer.lock` when the dependencies are not on disk (Laravel, Symfony, Magento). The verifier
lists every application with its version, grouped on the servers page and with its path and
sites on the server's page. With a release-based deploy (Capistrano, Deployer) only the release
a site serves is an application; the others are kept for a rollback. Its upload directory links to
the deploy's `shared` directory, which may itself lead to the volume the uploads live on: that is
followed and scanned, not reported as a suspicious link. Adding a
stack means adding a profile: markers to look for, public directory, upload and data directories,
files to read the version from.

For each application the `web` collector produces:

- a **hash tree** (Merkle) of the code, with directory hashes down to the second level: a line
  changed in a dependency changes the hash of its directory and the overall one, while uploads,
  cache and logs stay out of it;
- **scripts in upload directories** (`.php`, `.phtml`, `.phar`, `.jsp`, `.aspx`, double
  extensions such as `shell.php.png`) and **code inside files that are not scripts**, such as the
  serialized sessions used by deserialization exploits;
- **code in data files**: PHP the application was made to save in a session, a log, an error
  report or a cache file, waiting for an include of that file to run it. It takes a real open
  tag (`<?php` followed by a space or a line break, or `<?=`) and a webshell signature or a
  dangerous call after it, so logs of blocked requests and ordinary sessions are not reported;
  large logs are read through, within a budget per run;
- **polyglot images**: GIF, JPEG or PNG with code after the header or at the end;
- **webshell signatures**: `eval` of decoded payloads, commands run with request input, droppers
  that write code through library classes, includes of request input, of a URL or of
  `php://input`, `eval` of fetched content, calls through `$GLOBALS`, and function names such as
  `system` or `assert` written so that they do not appear in the source (split into pieces,
  escaped, built with `chr()` or XOR), matched after stripping comments from the source and
  checked on a corpus of clean applications; very long encoded blobs are reported separately as
  a weak indicator;
- **payment skimmers**: scripts, templates and SVG images among the files changed since the
  previous snapshot are read for payment fields (also when hidden in `atob` literals, split across them, reversed, in `fromCharCode` lists or
  escapes)
  with an exit to another host (`new Image`, `sendBeacon`, `WebSocket`, a request to an absolute
  URL) or with obfuscation (`atob`, `fromCharCode`, `new Function`, `eval`), and for live secret
  payment keys, large files in pieces; in a change of more than 50 scripts, generated bundles and
  packages updated as a whole (their version file changed with them) are left out and named, files changed elsewhere are still read; an
  SVG in an upload directory that runs script, under any namespace prefix, is reported as it lands;
- **changed code files by name**: with a state directory the sensor keeps a manifest of each
  application's code files and reports the files added, changed or removed since the previous
  delivered snapshot; a script added or changed alone is a high alert of its own, and scripts
  changed together, as a deploy changes them, are one high alert that names each with its hash
  (the first 20, the rest counted), the other files changed and the directories whose code
  changed, instead of an alert for each; the change of a directory's hash lists its files;
- **hidden files** among scripts and in data directories, except the tool configurations and
  test fixtures that libraries ship on purpose and the `._` metadata files macOS puts in the zips
  it makes (signatures are still searched in those);
- per-directory configuration files (`.htaccess`, `.user.ini`, `web.config`) with their hash,
  and a finding when they sit in an upload directory, naming the directives that make files run
  as scripts;
- applications nested in an upload or data directory, and suspicious symlinks. An upload
  directory that is itself a link to a directory inside the application or its deploy directory
  (`releases/5/uploads -> ../../shared/uploads`) is the usual deploy layout: it is followed and
  scanned, not reported. So is a script linked to its copy at the same path in the deploy's
  shared directory (`releases/5/wp-config.php -> ../../shared/wp-config.php`), when that copy is
  a regular file outside the upload and data directories with no webshell signature; a script
  linked to anything else stays a suspicious link.

`reachable` tells whether a file would be executed according to the configuration on disk. It is
a hint, never a reason to lower a finding's severity: whoever controls the configuration can
change it. Configurations modified after the web server started are flagged, because the running
one may differ: the file's inode change time, which no one sets back, against the start of the
server's newest workers, with two seconds for the rounding of the boot time.

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
- **code kept in the database**, which survives a cleanup of the files: the schema's triggers,
  stored procedures and functions and scheduled events on any framework; on Magento also
  integrations, the REST API tokens of administrators and integrations (never their values),
  layout updates and email templates, which Magento renders through its template engine, and
  customers whose names carry template code. Each object is reported with a hash its database
  computes over what it does, never with its body: for a token, over whom it acts for and
  hashes of its token and secret; an integration also carries its consumer and a digest of its
  role's rules. A new or changed one is an alert, including one taken over in place (a token
  moved to another administrator, an integration given more rules, a trigger redefined by
  another account): critical for a trigger on orders, quotes, payments, customers, settings or
  users, medium for an email template, high otherwise. A layout update or email template
  holding PHP, an executing call or the template filter callbacks of TrojanOrder-style attacks
  is critical even without a change;
- **administrators changed**: a new name, email or active flag of an existing administrator is
  an alert, since a changed email is how an account is taken over through a password reset;
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
path traversal, PHP-CGI options in the query string (`-d allow_url_include=1`, written with a
soft hyphen for CVE-2024-4577), SQL injection, injection probes, PHP code sent in a request (meant for a log or
cache the application includes), known scanners and HTTP libraries (a weak signal, low), brute
force on public logins and known exploit chains, correlated by IP: a session file uploaded through
the customer address form and loaded by a failing guest cart call, a cart item added through the
REST API followed by a fetch from `media/custom_options` by the same address (the attached file is
in the request body, which no log shows), and a shipping estimate for a guest cart whose ID is not
one the shop hands out (the shape of the XML external entity exploit against the address parser,
whose outcome the status does not tell). Magento's front controller prefix (`/index.php/rest/...`)
is matched too. Critical and high events are alerts; of the medium ones, those aimed at the
application's own weak points (a made-up cart's shipping estimate, PHP sent in a request, a file
attached to a cart item, a POST to a static file) raise one medium alert a day per rule and log,
shown on the verifier and not mailed, while the scans every site receives all day are only kept
in the snapshot. The severity of a script in uploads does not depend on the
HTTP status, which the script itself decides. For each requested script the sensor also says
whether it exists in the document roots of the nginx or Apache sites writing that log (with
nginx's location roots and aliases, Apache's `Alias`): a request that failed for a script found
in none of them ran no code, and raises no alert (scanners probe thousands of such paths). Nor
does a failed request on an nginx site that answers every request itself (`return`, the redirect
to HTTPS) or hands that path to a proxy: the backend's own log, read when it is on the host,
judges what ran there. The same probe often lands in several logs (http and https logged apart, a
proxy and the site behind it each logging it): the logs of sites that only answer or pass
requests on are left aside, and the script is looked up in the roots of the others, so a failed
probe for a script found in none of them raises nothing. The alert names the
file on the host the script would be (behind a proxy, in the site answering the same domain,
often a container's) and says whether it is there. When the request may reach a proxy otherwise (`ProxyPass`, a rewrite with
the `P` flag, a named location a fallback leads to), a root
holds a variable, a mapping is not modelled (`AliasMatch`), or the server is Caddy, the answer is
left open and the request is judged as before. A web
shell used and deleted between two snapshots looks missing: its creation is seen by the
real-time watch of the upload directories.

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
Across 43 attack scenarios reproduced in a Debian container (commit `e227079`), how many each
tool detects with its default configuration:

![Scenarios detected out of 43: tripwatch 43, AIDE 35, rkhunter 4, debsums 1](bench/detection.svg)

| Category | Scenarios | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|:-:|
| Persistence | 13 | 13 | 13 | 2 | 0 |
| Privileges | 4 | 4 | 4 | 0 | 0 |
| System integrity | 5 | 5 | 5 | 1 | 1 |
| Processes and network | 6 | 6 | 1 | 1 | 0 |
| Web applications | 11 | 11 | 11 | 0 | 0 |
| Limits: attacks between two checks, and traps | 4 | 4 | 1 | 0 | 0 |
| **Total** | **43** | **43** | **35** | **4** | **1** |
| **Named** | | 38 | 0 | 3 | 0 |

Named means the output identifies the technique, not only the changed file; method in bench/RESULTS.md.

Noise on routine changes (a plugin update, a package with a hook, log rotation, a deploy), reported beyond the clean run:

| Routine change | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|
| Update of a WordPress plugin, its version and sixty files rewritten | 1 | 0 | 0 | 0 |
| Installation of a package that ships a login hook | 1 | 6 | 0 | 0 |
| Rotation of the system logs, as logrotate does every night | 0 | 4 | 0 | 0 |
| Deploy that rewrites the site's code with a new release | 1 | 0 | 0 | 0 |

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
  signed event and every gap between two heartbeats over 100 seconds becomes an alert (unless a
  start of the sensor falls in it, which is judged on its own), so even a stop or a suspension
  shorter than the silence threshold leaves a trace; a sensor that is
  stopped says so in a last signed event, and one removed with its package (`apt remove`,
  `dnf remove`) raises a high alert at once instead of only falling silent; each start is judged
  against how the previous run ended, from what the sensor signed as it stopped: only a stop made
  while systemd was shutting the system down, followed by a new boot, is one low "Server was off"
  event (a server switched off every night raises no more), and only a stop for an update of the
  package, followed by a new version, is a low "Sensor updated", or only a line in the audit
  log when it is the version the console ordered. A service stopped on a running
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

- Container storage (`/var/lib/docker` and similar) is not examined yet: the `containers`
  collector reads only how containers are configured, not what changed inside them compared
  with their image. Between snapshots, containers are listed once a second: one created and
  removed within that second can be missed.
- In the scratch directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/lock`) the watch sees
  executable files, as anyone can write there: a file run without its execute bit (through the
  dynamic loader or an interpreter), one created with `O_TMPFILE` or in memory (`memfd`), one in
  a private tmpfs of a user namespace, or one removed within a millisecond, before the sensor
  reads it, is not seen there; a process still alive from such a file shows in the snapshot's
  processes. Past 2,000 events a second there the rest is counted as lost and reported.
  Directories more than two levels deep are not watched and are reported, except below a
  directory only root can enter (such as the private `/tmp` snapd keeps for each snap).
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

How long things are kept is set in days, from 1 to 3650, in the verifier's environment, and the
console states it where it matters: `TRIPWATCH_KEEP_SNAPSHOTS_DAYS` (30, at least 2),
`TRIPWATCH_KEEP_EVENTS_DAYS` (7), `TRIPWATCH_KEEP_RESOLVED_DAYS` for resolved critical and high
alerts (90) and `TRIPWATCH_KEEP_RESOLVED_MINOR_DAYS` for resolved medium and low ones (7, no
more than the others). Snapshots that are evidence of an open alert stay past their retention.

Content references are off by default. With `TRIPWATCH_CONTENT_REFERENCES=on` the verifier
compares the changed files of each WordPress plugin and theme, of WordPress itself outside
wp-content, and of each drupal.org module, theme and profile,
with the release as published (the core's from its official archive, checked against the MD5
list of api.wordpress.org): a
file with the SHA-256 the release lists at its path is the update's own and raises nothing, one
the release does not have, or has with other content, raises a high alert naming the release,
and a package the server never had, or whose version went down from the last the verifier saw,
raises a medium one: published does not mean harmless, and the verifier remembers each server's
releases across snapshots. The checksums come from
`downloads.wordpress.org` only, once per release for all the servers, kept in the database
(2 GB at most, the least used dropped first), at most five fetches per analysis round and fifty
per server a day; a release the source lacks is asked again after a day. Turning it on tells
WordPress.org which plugins and versions the servers run. Webshell signatures and the skimmer
search still read every changed file.

More users are invited from the console (Settings, Users). A new password, or a first
administrator, from the command line:

```sh
docker compose exec verifier /tripwatch-verifier user -email colleague@example.net
```

A user who lost both their phone and their recovery codes, when no administrator can reset it in
the console, has their second factor turned off with:

```sh
docker compose exec verifier /tripwatch-verifier user -email colleague@example.net -reset-2fa
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
  "update available" when it is older than the verifier, with the command to run), the address
  its sensor connects from (on clouds with NAT, the public address no interface holds) and its
  interface addresses, the web applications grouped by framework and version (stacks first, with
  how many of each), the last heartbeat and snapshot and the number
  of alerts; revoked servers listed apart. A search finds servers by name, address, system,
  sensor version, technology and the domains they serve; the list narrows to servers with alerts,
  silent ones or sensors to update, and sorts by name, worst severity, number of alerts or the
  quietest first.
- **Server.** State, the system as the sensor read it (with the package manager and count, the
  listening ports, the web applications and whether the real-time watchers run), its critical,
  high and medium alerts, then apart its health notes (the low findings) and its sensor's
  activity (updates, restarts after a shutdown, the first start), what each collector could not
  check in the last snapshot (work left undone, which also raises one low "Analysis incomplete"
  alert per collector, apart from notes such as a network filesystem skipped by design),
  the latest real-time events, the silences of the last 7 days with
  their duration, the last snapshots received, revocation.
- **Alerts.** To handle, acknowledged, resolved. A filter bar narrows the list by severity (low
  notes are left out unless ticked, and counted), server, category (web requests, web files,
  real-time, access, persistence, processes, network, privileges, packages, applications, sensor)
  and free text found in the server, title or detail (an address, a domain, a path), and orders it
  by severity, date, repetitions or server; every filter stays in the page address, so a view
  can be kept and shared. Each alert shows its category as a tag and its server with a colour of
  its own, the same on every page. At the side (above the list on smaller screens)
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
- **Notifications.** Where alerts are sent as they are raised: email (SMTP with TLS), Telegram
  chats and webhooks (a JSON body with a `text` field for chat tools and the alerts, signed with
  HMAC-SHA256 of the body in the `X-Tripwatch-Signature` header as `sha256=<hex>`). Each channel
  receives the alerts at or above its severity raised after it was added, can be tested, turned
  off and removed, and shows its latest send or the error; a channel that fails raises an alert.
  The email configured with `TRIPWATCH_SMTP_*` keeps working and is listed read-only.
  A channel's settings, passwords, bot tokens and webhook secrets among them, are sealed in the
  database with AES-256-GCM: the key is `TRIPWATCH_SECRETS_KEY` (32 bytes in base64, so it can
  be kept outside the data volume) or, without it, `pki/secrets.key`, made on the first start
  next to the CA's key and copied by `backup`. A copy of the database alone holds none of them;
  a channel sealed with another key is listed as unreadable and sends nothing until added again.
- **Server names, labels and notes.** Administrators give a server a name people use, labels as
  key=value pairs and a note, from its page; the name shows everywhere, the identity in the
  certificate stays, and searches find all three. The server list groups by a label key, one
  section per value.
- **Users and audit log.** Three roles: viewers read, operators also handle alerts,
  administrators also enroll and revoke servers, order sensor updates, set up notifications and
  manage users. Administrators invite people with a one-time link (three days) in which they
  choose their password, change roles and remove accounts; there is always one administrator
  left. A viewer or an operator can be limited to the servers carrying one label: everything
  else stays out of their lists, counts, charts and searches, and out of reach. The audit log
  keeps who did what in the console, newest first.
- **Export.** The alert list, as filtered and in its order, downloads as CSV or JSON, every
  page of it up to 10,000 alerts (the file says when it stops there). Cells of the CSV that a
  spreadsheet would run as a formula, since titles and details carry what the server wrote,
  start with an apostrophe. Each export is in the audit log.
- **API.** Administrators make tokens (Settings, API tokens) that programs send as
  `Authorization: Bearer twk_...`: `GET /api/v1/alerts` (filters `status`, `severity`, `host`,
  `limit`; `total` counts every match; with `after=<id>` alerts come in the order they were
  raised from the one after it, and `next` is the cursor of the following page, so a program
  reads every alert once), `GET /api/v1/alerts/{id}`, `GET /api/v1/hosts`, and with write access
  `POST /api/v1/alerts/{id}/ack` and `/resolve`. A token acts as the person who made it, the
  servers they may see included, is shown once, expires, and can be revoked.
- **Metrics.** `GET /metrics` serves Prometheus' text format to an API token, sent the same
  way (`authorization` with `type: Bearer` in a scrape config): servers by state (reporting,
  silent, waiting for a first heartbeat, revoked), alerts not resolved by status and severity,
  snapshots waiting for analysis and how long the oldest has waited, the database's size, the
  sensors' requests since the start by kind and answer, and the messages sent to or failed on
  each kind of notification channel. A token limited to some servers
  counts only theirs.
- **Account.** Each user can set up a second factor (an authenticator app, with ten single-use
  recovery codes): signing in then asks a code after the password, five wrong codes end the
  attempt and refuse the account's codes for 15 minutes (each wrong one after that again),
  whatever the session or the address, and a code works once. A browser becomes a known one
  only once its code is given, and replacing the second factor takes turning it off with a
  current code; setting it up or having it reset signs the account out everywhere else. The page lists the sessions of the account and signs out any
  of them; administrators can reset the second factor of someone who lost their phone.
- **Enroll server.** Generates the one-time token with the command to run on the server, or the
  bundle with the keys to download once; the verifier keeps neither.

A search box at the top of every page looks for a text across the fleet at once: servers (name,
address, system, applications and the sites they serve), alerts of every status (server, title,
what the server reported) and the newest 50,000 real-time events (path, command). A search runs
at most five seconds, on read-only connections of its own, so it never holds up what the
servers send.

Keys: `/` jumps to the search box; `j` and `k` move down and up the rows of an alert list, and
Enter opens the alert or the group under the cursor.

A dark operations console in the colours of the logo, a fingerprint with one broken ridge: teal
for what can be used or is selected, coral and amber only for the severities. The menu groups
operations (overview, alerts, servers) and configuration (enrolling a server). It refreshes by
itself every minute and works on a phone too. The mark in the menu and the browser tab icon carry
a coral dot while a critical alert is open; a verifier without email shows it as a warning in the
menu. Fonts (IBM Plex) are embedded in the binary and served by the verifier. Pages run no inline scripts or styles (strict Content Security
Policy), forms are protected by CSRF tokens, and sign-in attempts for the same email address go
through one at a time, with a delay that grows after five failures up to 15 seconds, whatever
address they come from: guessing the password becomes very slow even in parallel. A browser that
has already signed in has a lane of its own, which no attack slows down, so the user is never
locked out.

### Email

With `TRIPWATCH_SMTP_HOST` set, critical and high alerts arrive by email, grouped into one message
per round, with a link to the detail. If sending fails, the interface shows it as a verifier
alert. Names that come from the server (files, processes, requests) cannot forge lines of the
message or hide their real order: line breaks, control characters and invisible format
characters such as right-to-left overrides are stored as visible escapes (`\x0a`, `\u202e`),
in titles and details alike, and the body is sent as quoted-printable, so no line exceeds the
limit mail servers enforce however long a path is.

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
4. Containers: differences of running containers from their image.
5. Kubernetes and AWS: DaemonSet, audit logs, CloudTrail, VPC Flow Logs.
6. External checks and canary tokens.
7. rpm ndb databases (SUSE).
8. PostgreSQL databases for the application profiles (Django, Rails, Drupal on PostgreSQL).
9. Content references for application code: the verifier, which unlike the sensor may reach the
   network, compares the hashes of changed files of a CMS core, its plugins and themes with the
   checksums their registries publish, so that a package update is told apart from code written
   into the package with its version file touched.

## Status

Early development, usable end to end. Implemented and tested: the envelope protocol, environment
and web stack discovery, the system, web, log and application collectors, the sensor as a
service with real-time events for critical paths and process starts, the verifier with rules,
alerts, email and web interface. The next step is eBPF events on recent kernels.

## License

[Apache License 2.0](LICENSE). The embedded IBM Plex fonts are under the SIL Open Font License
1.1, included as [internal/verifier/ui/static/fonts/OFL.txt](internal/verifier/ui/static/fonts/OFL.txt).
