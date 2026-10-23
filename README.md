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
  old or unpatched distributions. It sends a heartbeat every minute and a full state snapshot
  every hour; real-time critical events are on the roadmap.
- **The verifier decides, off the server.** Baselines and build manifests live where an attacker
  with root on a monitored server cannot rewrite them. The verifier holds no credentials to log
  into the servers: the sensors push their data to it.
- **Every message is signed and linked to the previous one.** A lost, replayed or forged message
  breaks the chain, and a silent sensor is already an alert.

A file is legitimate only if it traces back to the system package manager, to a signed deploy
manifest produced by the build (checked against the lockfile: `composer.lock`,
`package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`, ...) or to a container image digest.

## Getting started

Every release publishes the sensor as `.deb` and `.rpm` packages and the verifier as a container
image (`ghcr.io/cpibia/tripwatch-verifier`). Nothing needs to be cloned or compiled on the
servers. The commands below use release `0.1.0`: take the current number from the
[releases page](https://github.com/cpibia/tripwatch/releases).

### 1. Install the verifier

You need a dedicated machine with Docker (a small VPS is enough), outside the servers you will
monitor, and a DNS name pointing to it, here `tripwatch.example.net`.

```sh
mkdir tripwatch && cd tripwatch
curl -fsSLO https://github.com/cpibia/tripwatch/releases/latest/download/docker-compose.yml
curl -fsSL -o .env https://github.com/cpibia/tripwatch/releases/latest/download/verifier.env.example
```

In `.env` set at least the release, the name the sensors will use, the public addresses and the
first user:

```sh
TRIPWATCH_VERSION=0.1.0
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

### 2. Install the sensor

On every server to monitor, as root.

Debian and Ubuntu:

```sh
curl -fsSLO https://github.com/cpibia/tripwatch/releases/download/v0.1.0/tripwatch-sensor_0.1.0_amd64.deb
apt install ./tripwatch-sensor_0.1.0_amd64.deb
```

RHEL, AlmaLinux, Rocky, Fedora and Amazon Linux:

```sh
dnf install https://github.com/cpibia/tripwatch/releases/download/v0.1.0/tripwatch-sensor-0.1.0-1.x86_64.rpm
```

On ARM servers use `arm64` in the `.deb` name and `aarch64` in the `.rpm` name. The package
installs `/usr/bin/tripwatch-sensor` and its systemd unit, and creates `/etc/tripwatch`; the
service starts only after enrollment. On other distributions use the static binary from the
release (`tripwatch-sensor_0.1.0_linux_amd64`) with the unit in [deploy/systemd](deploy/systemd).

Every file of a release is listed in `SHA256SUMS` and has a build provenance attestation, which
proves it was built by this repository's release workflow from the tagged source:

```sh
gh attestation verify tripwatch-sensor_0.1.0_amd64.deb -R cpibia/tripwatch
```

### 3. Enroll the server

In the web interface open "Registra server", choose the server's name and run the command it
shows on the server, as root:

```sh
echo 'tw1....' | tripwatch-sensor enroll -token-file - && systemctl enable --now tripwatch-sensor
```

The server shows up in the overview with its first heartbeat within a minute; the first full
snapshot follows shortly.

### Updating and removing

- **Sensor:** install the package of the new release the same way; a running sensor is
  restarted. `apt remove tripwatch-sensor` or `dnf remove tripwatch-sensor` stops and removes it,
  and keeps the bundle in `/etc/tripwatch` and the state in `/var/lib/tripwatch`, so a reinstall
  resumes the same chain.
- **Verifier:** set the new `TRIPWATCH_VERSION` in `.env`, then
  `docker compose pull && docker compose up -d`. The state stays in the `data` volume.

To see what the sensor collects without a verifier, run `sudo tripwatch-sensor > snapshot.json`
on any Linux machine.

## What the sensor collects

| Collector | What it reports |
|---|---|
| `accounts` | users, UIDs, groups (including members, administrators and group passwords from `/etc/gshadow`) and password state (set, locked, empty); hashes are never collected |
| `ssh` | sshd settings read the way sshd reads them (`Include` followed where it appears, first value wins), `Match` blocks reported in full, every authorized key of every account with fingerprint, comment and options such as `command=` |
| `sudoers` | sudo rules, following `#include`, `@include` and `#includedir` wherever they point, and the other policies that give a user root: polkit rules and `.pkla` files (used by `pkexec` and `systemd-run`), `doas.conf`; owner, mode and ACLs of the policy files and of every directory above them up to `/`, also along links. A file or directory writable by a user other than root is a critical alert: owner, an ACL granting write to a user or group, a writable group with at least one member other than root. polkitd is trusted only on polkit's directories, and only if it is a system account without a shell and with a UID of its own; a group that can write a policy becomes privileged. The full line diff is stored with the alert and shown on its page |
| `scheduled` | system and user crontabs, `cron.daily` and similar scripts, pending `at` jobs |
| `services` | systemd units and override drop-ins, system, transient and per-user, with their `Exec*` commands and activation links; generators; `system.conf` and `user.conf` with their `DefaultEnvironment` |
| `hooks` | `ld.so.preload`, `rc.local`, `profile.d`, PAM, `update-motd.d`, package manager hooks, the shell rc files of every account |
| `processes` | every process with its executable (flagged if deleted from disk), hash, working directory, `LD_PRELOAD` and namespaces; command lines with passwords, tokens and credentials redacted; kernel threads (kernel flag) are only counted, processes imitating their names are listed |
| `sockets` | listening sockets, open connections and pending outbound attempts, in every network namespace (containers included), mapped to their process |
| `packages` | system files that no longer match the package database (dpkg, apk), a fingerprint of the database itself, executables and symlinks no package owns, hidden entries under `/usr` |
| `privileged` | a scan of the whole filesystem (including the world-writable directories in `/run` and `/dev/shm`) for setuid and setgid binaries, files with Linux capabilities, immutable and append-only files; files on a FUSE filesystem mounted by a user other than root are marked with that mount, since that user chooses their owner and mode |
| `weblog` | web server access and error logs, read incrementally: attack events grouped by rule, IP and path, statistics on IPs and POST targets |
| `apps` | for WordPress, Magento, Drupal and Laravel: administrators in the database, active extensions, scripts stored in settings and content with the domains they load from or send to, development settings left on in production |
| `web` | inventory of sites and applications, and for each application: hash tree of the code, scripts in upload directories, polyglot images, webshell signatures, hidden files, scripts the web server actually executes |

The sensor also detects the environment it runs in (host, container, Kubernetes, Fargate) and the
container runtimes present.

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
- **hidden files** among scripts and in data directories;
- per-directory configuration files (`.htaccess`, `.user.ini`, `web.config`) with their hash,
  and a finding when they sit in an upload directory, naming the directives that make files run
  as scripts;
- applications nested in an upload or data directory, and suspicious symlinks.

`reachable` tells whether a file would be executed according to the configuration on disk. It is
a hint, never a reason to lower a finding's severity: whoever controls the configuration can
change it. Configurations modified after the web server started are flagged, because the running
one may differ.

The collector has been run on real applications of different stacks, up to more than 170,000
files per application. The remaining false positives are library files that really contain those
patterns (for example code analysis tools that search for `preg_replace` with `/e`): the
verifier's baseline recognizes them as known after the first snapshot.

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
Across 29 attack scenarios reproduced in a Debian container (commit `78d624e`), how many each
tool detects with its default configuration:

![Scenarios detected out of 29: tripwatch 27, AIDE 24, rkhunter 4, debsums 1](bench/detection.svg)

| Category | Scenarios | tripwatch | AIDE | rkhunter | debsums |
|---|:-:|:-:|:-:|:-:|:-:|
| Persistence | 10 | 10 | 10 | 2 | 0 |
| Privileges | 4 | 4 | 4 | 0 | 0 |
| System integrity | 5 | 5 | 5 | 1 | 1 |
| Processes and network | 3 | 3 | 0 | 1 | 0 |
| Web applications | 4 | 4 | 4 | 0 | 0 |
| Limits: attacks between two checks, and traps | 3 | 1 | 1 | 0 | 0 |
| **Total** | **29** | **27** | **24** | **4** | **1** |

Detects means the data about the attack appears in the output of the tool; for tripwatch the
judgement stays with the verifier. The scenarios in the "Limits" category (a dropper or an SSH key
that appear and disappear between two checks) measure the limit of every tool that compares states,
tripwatch included. Method, results per scenario, versions and cost in [bench/RESULTS.md](bench/RESULTS.md).
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
  stop or a suspension shorter than the silence threshold leaves a trace;
- critical and high alerts do not close by themselves when the condition goes away: a
  compromised server could clean up and silence its own alerts, so a person closes them.

Coming next:

- privilege escalation events shipped as they happen, before the attacker can act on the sensor
  (until then, what happens between two snapshots, such as a process that lives a few seconds, is
  not seen);
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
- The sensor produces snapshots: what appears and disappears between two runs is not seen until
  the real-time event stream lands.
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

## Build

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

## Verifier

The verifier runs on a dedicated machine, outside the monitored servers, as a `docker-compose`
stack. It exposes two ports:

- `8443`, the sensors' ingest: TLS 1.3 with a mandatory client certificate, signed by the
  verifier's private CA. It must be reachable from the monitored servers.
- `8080`, the web interface over HTTP, published on `127.0.0.1` only: expose it through an HTTPS
  reverse proxy (nginx, Caddy, Traefik) or reach it with an SSH tunnel.

```sh
cp .env.example .env      # release, names, public URLs, first user, SMTP
docker compose up -d
```

To run a build of your own checkout instead of the published image:

```sh
cd deploy/verifier
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

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

The interface is in Italian.

- **Overview.** A control room board: everything is grey until something deviates. At the top
  the counters (critical, silent, high, acknowledged, each with the age of the oldest); below, the
  server table with deviating servers on top and the oldest first; then the alerts to handle. On
  wide screens, at the side, the detail of the alert to look at first, with its actions; clicking
  another alert (also from the Alerts page) shows that one in the panel, with a link to its
  detail. Every severity has a shape as well as a color (diamond for silent, triangle critical,
  square high, circle medium, hollow circle low), and a silent server is a present mark with a
  dashed row, not a dimmed row.
- **Server.** State, every alert, the silences of the last 7 days with their duration, the last
  snapshots received, revocation.
- **Alerts.** To handle, acknowledged, resolved. Every alert can be acknowledged and resolved;
  the detail shows the text collected from the server as data, without interpreting it.
- **Enroll server.** Generates the one-time token with the command to run on the server, or the
  bundle with the keys to download once; the verifier keeps neither.

Light and dark theme (follows the system, or chosen from the menu), refreshes by itself every
minute and works on a phone too. Pages run no inline scripts or styles (strict Content Security
Policy), forms are protected by CSRF tokens, and sign-in attempts for the same email address go
through one at a time, with a delay that grows after five failures up to 15 seconds, whatever
address they come from: guessing the password becomes very slow even in parallel. A browser that
has already signed in has a lane of its own, which no attack slows down, so the user is never
locked out.

### Email

With `TRIPWATCH_SMTP_HOST` set, critical and high alerts arrive by email, grouped into one message
per round, with a link to the detail. If sending fails, the interface shows it as a verifier
alert.

## Running the sensor

The recommended way is the token: in the interface ("Registra server") you choose the server's
name and get a command to run on the server, as root:

```sh
echo 'tw1....' | tripwatch-sensor enroll -token-file - && systemctl enable --now tripwatch-sensor
```

The sensor generates its own TLS key and signing key, checks that the verifier is the right one
by comparing its CA with the fingerprint in the token, and only then sends the secret and the
public keys; private keys never leave the server. The token is valid for one hour and once only,
and the verifier keeps only its hash. The token goes through standard input because any user on
the server can read a process's arguments; every enrollment raises an alert, and a token presented
again after use raises a critical one, because it means someone has a copy. On certificate
renewal, too, the new key is born on the server.

Alternatively the verifier generates a bundle with the keys already inside, from the interface or
from the command line:

```sh
(umask 077; docker compose exec -T verifier /tripwatch-verifier enroll -host web-01 -out - > web-01.json)
```

Copy the bundle to the server and start the service:

```sh
sudo install -o root -g root -m 600 web-01.json /etc/tripwatch/bundle.json
sudo systemctl enable --now tripwatch-sensor
```

The sensor refuses a bundle not owned by its user, readable by other users or with a verifier
address that is not `https`. The client certificate lasts two years and the sensor renews it by
itself in the last two months, without a restart and without touching the bundle. State kept
between runs (position in the chain, envelope awaiting acknowledgement, log positions) lives in
`-state-dir` (default `/var/lib/tripwatch`); every envelope is saved before being sent and resent
identical if the acknowledgement is lost.

Without `-bundle` the sensor prints a JSON snapshot and exits, useful to see what it collects:

```sh
sudo ./tripwatch-sensor > snapshot.json
```

On a Kubernetes node, mount the host root into the pod and tell the sensor where it is:

```sh
tripwatch-sensor -root /host
```

A systemd unit with security restrictions is in [deploy/systemd](deploy/systemd).

## Roadmap

1. Real-time events via eBPF or auditd, shipped as they happen.
2. Installation without a toolchain: signed `.deb`, `.rpm` and `.apk` packages and APT/YUM
   repositories (one-time token enrollment already exists), image and Helm chart for the
   DaemonSet; the verifier compares the running binary with the published release.
3. Signed deploy manifests produced by the build and checked against the lockfile.
4. Containers: differences of running containers from their image, privileged containers.
5. Kubernetes and AWS: DaemonSet, audit logs, CloudTrail, VPC Flow Logs.
6. External checks and canary tokens.
7. rpm package verification.
8. PostgreSQL databases for the application profiles (Django, Rails, Drupal on PostgreSQL).

## Status

Early development, usable end to end. Implemented and tested: the envelope protocol, environment
and web stack discovery, the system, web, log and application collectors, the sensor as a
service, the verifier with rules, alerts, email and web interface. The next step is real-time
events.

## License

[Apache License 2.0](LICENSE).
