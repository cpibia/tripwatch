# Architecture

tripwatch detects unauthorized changes on servers: new privileged users, SSH keys, persistence
(cron, systemd, SUID binaries, immutable files), application code changed without a deploy behind
it, webshells, skimmers and attack patterns in web server logs. It is stack independent: the core
knows nothing about languages or frameworks, and everything specific lives in profiles that are
activated when automatic discovery finds the matching technology.

## Components

**Sensor** (`cmd/tripwatch-sensor`): a static binary on every monitored machine. It observes and
reports, it never decides. As a service it sends a heartbeat every minute and a full snapshot
every hour, inside signed envelopes. In the future, critical events (users, keys, sudoers, setuid,
new units and cron lines, kernel modules) will be sent as soon as they happen.

**Verifier** (`cmd/tripwatch-verifier`): runs on a dedicated machine. It keeps baselines and build
manifests outside the monitored servers, compares, applies the rules and raises alerts. It has no
credentials for the monitored machines: the sensors send it their data.

## Transport

The sensor pushes to the verifier over TLS 1.3 with a client certificate (`internal/transport`).
Every envelope is sealed, saved to disk with `fsync` and an atomic rename, and only then sent: if
the acknowledgement is lost, the same envelope is sent again after a restart, and the verifier
recognises it and accepts it only once. The enrollment bundle holds the CA, the host's TLS
certificate and key, and an Ed25519 signing key, separate from the TLS one. The recommended
enrollment uses a one-time token created in the interface: the verifier's address, a secret valid
for one hour (stored only as a hash and consumed in a single statement) and the SHA-256
fingerprint of the CA. The sensor generates its own keys, opens the connection accepting only a
chain that ends in that CA (the verifier sends it after its own certificate) and sends the secret
and the public keys to `/v1/enroll`, the only path that does not require a client certificate; it
receives the client certificate and assembles the bundle itself. The client certificate lasts two
years: in the last 60 days the sensor asks for a new one on `/v1/renew`, authenticating with the
current one; the verifier issues it only in the last 90 days of validity and only to an enrolled,
unrevoked host. Every host is bound to the serial number of its current certificate: a new
enrollment makes all earlier ones unusable at once, a renewal keeps the old one valid only until
the new one is used, and a superseded certificate presented to the verifier raises an alert. The
new certificate lives in the sensor's state directory, the bundle in `/etc` stays read-only, and
the signing key does not change.

## Verifier

- **Ingest** (`internal/verifier/ingest`): the common name of the client certificate must be the
  identity declared in the envelope; signature and chain are verified with the enrolled key.
  Envelopes from the same host go through one at a time, and the position in the chain is updated
  only if it is still the one that was verified, so two envelopes cannot extend the same link. A
  snapshot beyond the third in 15 minutes is refused before any work is done. A broken or
  restarted chain is a critical alert.
- **Store** (`internal/verifier/store`): SQLite. All snapshots are kept for 48 hours; then, up to
  30 days, the last one of each day and those that show a change or a new condition together with
  the one before, even beyond 30 days while the most severe alert they show is still open; the
  first one of every host is kept forever as the baseline. Beyond 1 GB of snapshots in 24 hours a
  host is still verified but its snapshots are not kept, with an alert. Retention is by age and
  never by count, so a compromised host flooding snapshots cannot push the evidence out; hourly
  snapshots of a stable host are almost identical, and thinning them keeps the database at a few
  days' worth per host. Every minute in which a heartbeat or a snapshot arrives is recorded for 7
  days: the interface derives the silences of each host from it.
- **Analysis** (`internal/verifier/analyze`): a queue in the database, analysed in order. Every
  snapshot is decompressed with limits on size, number of values and depth, then compared,
  collector by collector, with the last snapshot in which that collector answered: making a
  collector fail once does not turn a change made in the meantime into the baseline. A collector
  that fails for 3 snapshots in a row raises a high alert that stays open even after it
  recovers; if none of the previous 50 snapshots has its result, a high alert says the comparison
  was not possible. Rules produce conditions (a state that is dangerous in itself, closed when it
  disappears, except critical and high ones) and changes. Every minute a check raises the alert
  for silent hosts and for those that send heartbeats but no more snapshots.
- **Alerts**: one fingerprint per condition and host; the same condition updates the existing
  alert instead of creating a new one, and reopens it if it was resolved, unless it was accepted.
  An acceptance (`accepted` table) binds a host and fingerprint to a hash of the alert's detail,
  without process numbers: while a new snapshot produces the same detail, `Store.Raise` drops
  the alert; a different detail deletes the acceptance and raises it. What the verifier and the
  sensor's lifecycle report (silences, chains, sensor events, aggregates) cannot be accepted.
- **Notifications** (`internal/verifier/notify`): critical and high alerts by email, one message
  per round.
- **Interface** (`internal/verifier/ui`): server-rendered HTML, templates and assets embedded in
  the binary, no frontend build. Colour appears only on deviations and every severity also has a
  shape. 12-hour sessions with tokens stored only as hashes, a CSRF token derived from the
  session, an origin check on forms, sign-in attempts queued per address with a growing delay
  (never a lockout), and a Content Security Policy with no inline scripts or styles: text
  collected on the servers may be written by an attacker and is always shown as data.

## Sources of truth

A file is legitimate only if it traces back to one of these sources:

1. the system package manager (dpkg, rpm, apk checksums);
2. a signed deploy manifest produced by the build, for any language, checked against the lockfile
   (`composer.lock`, `package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`, ...);
3. the digest of a container image: anything in a running container that differs from the image
   is drift.

## Trust model

An attacker with root on a monitored server can stop its sensor or impersonate it. tripwatch does
not try to prevent this, it makes it visible:

- envelopes are signed and linked in a hash chain (`internal/protocol`): lost, replayed or forked
  messages are detected, and a missing heartbeat is an alert;
- critical and high alerts are closed only by hand, because a compromised server could clean up
  the condition that raised them;
- privilege escalation events are sent before the attacker can act on the sensor;
- checks that do not run on the server (pages fetched from outside, the provider's APIs, canary
  tokens, disk snapshots verified offline) cannot be silenced from there.

## Reading files safely

The sensor runs as root but reads files that an unprivileged user can create or replace. Every
collector goes through a single view of the filesystem (`rootFS` in `internal/collector`):

- on Linux the path is first resolved with `O_PATH`, which does not open the file: a device or a
  FIFO undergoes no operation at all. `fstat` on the descriptor reads its type, and only regular
  files and directories are reopened for reading, through `/proc/self/fd`, on the same inode;
  reads are `O_NONBLOCK|O_NOCTTY` in any case;
- when the observed root is not `/` (a DaemonSet with `-root /host`) symlinks are resolved inside
  that root, as they would be on the host and not in the sensor's container: with `openat2` and
  `RESOLVE_IN_ROOT` when the kernel offers it, otherwise (old kernel, `openat2` forbidden by
  seccomp) with a userspace resolver that works on descriptors as the kernel does: each component
  is opened with `openat` on the descriptor of the previous directory with `O_NOFOLLOW`, symlinks
  are read from their own descriptor, and `..` walks back on a stack of descriptors without going
  above the root. In that case the snapshot still carries a warning (`warnings`), because the
  confinement does not come from the kernel. `/proc` is the exception: its special links are
  needed by the process collector;
- `Lstat` and `ReadLink` resolve the parent directory the same way and read the last component
  through its descriptor, so an intermediate link cannot lead outside the root;
- `ReadFile` refuses files beyond `MaxReadSize` with an error, never with a truncated result;
  `ReadDir` stops beyond a maximum number of entries and says so;
- the hash is computed up to `MaxHashSize`; beyond that, the file is reported without a hash and
  with an explicit error, and the web collector uses size, ctime and inode as the fingerprint
  (mtime can be set back without privileges, ctime cannot), reading only the head and tail of the
  file;
- every collector runs with a timeout (`collector.Timeout`): a stuck one does not stop the
  others.

## Web stack

Discovery (`internal/discovery`) reads the nginx, Apache and Caddy configurations following their
includes, resolves variables (nginx `set $MAGE_ROOT`, Apache `envvars`) and produces a list of
sites with document root, logs and upstreams. For nginx it keeps the tree of `location` blocks and
queries it in the same order nginx does (exact match, longest prefix, `^~`, regexes in file
order, nested regexes before outer ones): `Site.Executes(uri)` tells whether a request reaches the
interpreter. For Apache and Caddy it is enough to know whether there is a PHP handler.

Applications are recognised through profiles: markers that must exist, the public directory,
upload directories, data directories and the files to read the version from. Specific profiles
come before generic ones, and site roots are tried from the outermost to the innermost, so
Magento's `pub` is not mistaken for a PHP application of its own.

The `web` collector walks each application only once. Every file is read once: the same content
serves both the hash and the checks. The hash tree covers the code and leaves out the data
directories, which change on their own; data directories are inspected anyway. Generic upload
names (`uploads`, `media`, `files`...) count only under the application root or the web root, and
only when the profile does not say where uploads go: deeper down they are ordinary code
directories.

Before any content is read, a pass lists only the names in the upload directories and reports the
scripts: it costs only the listing, so files that are slow to read (sparse files, millions of
images) cannot push a webshell past the deadline. The content pass then enriches the same
findings with signatures, or withdraws them if the file is an empty placeholder. Data directories
are read as a stream and not hashed; a code directory with more entries than the limit is
inspected the same way. Inside uploads, symlinks are reported and never followed; the only link
followed is an upload directory that is itself a link, and only towards the application or the
directory that holds its releases. That link is not a finding when it leads to a directory there;
one leading anywhere else, or named like a script, is.

## Web server logs

`internal/weblog` does no I/O: it turns a line into a normalised request (combined format and
Caddy JSON, path decoded twice against double encoding) and applies the rules, with a bounded
per-IP state to correlate chains. The verifier will use the same code on raw logs.

`internal/collector/logs` reads files with a cap per line (`MaxLineLength`; beyond it, it skips to
the next line without keeping the bytes in memory), per file and per round, and with bounded maps
during the scan. Together with the offset it saves the hash of the last 4 KB read: on the next
round, if those bytes changed or the file is shorter than the offset, the log was rewritten or
truncated in the same inode, and that is an event. On rotation it looks for the old file among
its siblings by inode (`.1`, `dateext`, Caddy's dated names) and reads its tail from the saved
offset; a file emptied in place with a copy next to it whose content matches the saved
fingerprint is `copytruncate`, not a truncation. If the previous file cannot be found, it says
so. A stretch without a newline longer than the per-round limit is skipped with an issue instead
of stalling the offset. Events are capped: beyond the cap an event gets in only in place of a
strictly less severe one, so a flood of events of one severity does not keep out more severe
ones. IPs are counted with a Misra-Gries summary, and the rules' per-IP tables evict instead of
refusing. For a line beyond the limit, head and tail are kept: the head holds method, path and
status, the tail a real line written after a hole of null bytes, which web servers never write and
which are treated as a separator. A copy used to recognise `copytruncate` counts only if the owner
of the log could not write it. New positions stay pending until the caller confirms delivery of
the snapshot with `Commit`: a lost round is read again.

## Applications

`internal/collector/apps` is the only collector that opens connections: to the database of the
recognised applications, with the credentials from their configuration. Queries are `SELECT`
only, with validated table prefixes and parameters passed as arguments; results are limited to a
few hundred rows per query. For the host `localhost` the Unix socket inside the observed root is
used, as the `mysql` client does. Values taken with `getenv()` are resolved from the environment of
the PHP processes and their ancestors. Queries go through an interface (`querier`), so tests do
not need a database.

## Package layout

| Package | Role |
|---|---|
| `internal/protocol` | envelope format, signing, chain verification |
| `internal/discovery` | runtime environment, container runtimes, the machine's system (distribution, kernel, resources, addresses), nginx, Apache and Caddy sites with their routing, applications and active runtimes |
| `internal/collector` | collector contract, snapshot, file description (hash, owner, inode flags) |
| `internal/collector/system` | accounts, SSH, sudoers, cron and at, systemd units, startup hooks, processes, sockets, package verification, privileged files |
| `internal/collector/web` | for each application: code hash tree, uploads, polyglots, webshell signatures, hidden files, reachable scripts |
| `internal/weblog` | access log parsing, attack rules, request redaction |
| `internal/collector/logs` | incremental, bounded log reading, events, statistics, committed positions |
| `internal/collector/apps` | application configuration and database: administrators, stored scripts, extensions, settings |
| `internal/transport` | sealing, saving and sending envelopes from the sensor |
| `internal/verifier/pki` | private CA, server certificate, enrollment bundles |
| `internal/verifier/ingest` | mTLS ingest and chain verification |
| `internal/verifier/store` | SQLite store: hosts, snapshots, activity, alerts, users, sessions |
| `internal/verifier/analyze` | bounded snapshot decoding, rules, sensor silence |
| `internal/verifier/notify` | alert emails |
| `internal/verifier/ui` | web interface |
| `internal/buildinfo` | version stamped at build time |

`deploy/verifier` holds the verifier's Dockerfile and `docker-compose.yml`, `deploy/systemd` the
sensor's unit. Planned: `internal/collector/...` for containers, a Kubernetes DaemonSet.
