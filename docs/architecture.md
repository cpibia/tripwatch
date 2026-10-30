# Architecture

tripwatch detects unauthorized changes on servers: new privileged users, SSH keys, persistence
(cron, systemd, SUID binaries, immutable files), application code changed without a deploy behind
it, webshells, skimmers and attack patterns in web server logs. It is stack independent: the core
knows nothing about languages or frameworks, and everything specific lives in profiles that are
activated when automatic discovery finds the matching technology.

## Components

**Sensor** (`cmd/tripwatch-sensor`): a static binary on every monitored machine. It observes and
reports, it never decides. As a service it sends a heartbeat every minute, a full snapshot every
hour and, on Linux, real-time events, inside signed envelopes of one chain.

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
  snapshot is decompressed with limits on size, number of values and depth, the values bounded
  per collector result too (500,000 each, 1,000,000 decoded together, smallest first), so a
  result an unprivileged user inflates is refused alone, named as that collector's error, and
  never takes the rest of the snapshot with it; then it is compared,
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
- changes to critical paths and suspicious process starts leave the server within two seconds,
  before the attacker can act on the sensor;
- checks that do not run on the server (pages fetched from outside, the provider's APIs, canary
  tokens, disk snapshots verified offline) cannot be silenced from there.

## Real-time events

`internal/watch` runs next to the snapshots. Files are watched with inotify on directories, never
on files, so a file replaced by a rename is still seen: each target names a directory, a class
(accounts, ssh, privilege, schedule, service, hook, upload) and optionally the entry names it
keeps. Upload directories are watched recursively down to eight levels, including directories
created later, whose contents are listed at once since a file can land there before the watch
exists. Watches are capped at 8,192, use `IN_DONT_FOLLOW` and `IN_ONLYDIR`, and the file behind an
event is described through the same confined view the collectors use, with `lstat` and no
following of the final component, so a planted link is reported and never read or opened, and
hashed only up to 1 MB and 16 MB a second, on the goroutine that reads the kernel's queue.
Directories the depth, count or watch limits leave out are reported in the watchers' status.
Each application's web root is watched too, without its subdirectories and for scripts only: a
script that appears there and is removed within the transient window is a probe that deletes
itself, which no snapshot would show; one that stays is named by the next snapshot's manifest.
After each snapshot the targets are set again from the
accounts' homes and the applications' upload directories.

Processes come from the netlink process connector (`PROC_EVENT_EXEC` and `PROC_EVENT_UID`), which
needs `CAP_NET_ADMIN` in the initial network namespace and no eBPF; the sensor drops the
capability on every thread once subscribed, since receiving needs none. Each new process is read from
`/proc` the way the processes collector reads it, command line redacted, at most 200 a second;
only those matching a reason are reported (`web_user_tool`, `unusual_path`, `deleted_executable`,
`privilege_gain`). For an interpreter the script it runs is reported as well, since `/proc` shows
the interpreter as the executable. A start identical to one reported in the last hour (same
reason, executable, script, parent, users, directory and full command line) is counted, not
sent, and the count goes with the next report of it: a job the web server's user runs every
minute costs 24 events a day instead of 1,440. The memory of starts is bounded at 1,024; when
it is full of recent ones, new starts are reported every time rather than held back.

Containers are not watched with inotify: their configuration is written after their directory
appears. Every second the watcher lists the containers of Docker (its data root taken from
`daemon.json`) and the OCI bundles of containerd, Podman and CRI-O, and reads, through the
confined view, only the ones it has not seen, at most 64 a look; a configuration still unreadable
after five looks is left out. A container is read again when its configuration changes (Docker
rewrites it at the start, containerd writes the task's PID): created with a harmless directory
and started with a link in its place, it is judged on what its process mounted. New containers
are read first; the reads again have a budget of their own, 64 a look, taken in turn through
the list, so containers a health check rewrites every second hold back neither. The first look only records what is there. A container whose
configuration gives it power over the host (`system.ContainerPowers`, the same function the
verifier's snapshot rule uses; the sensor only adds facts it alone can read: where a mount's
source leads through links, the host path behind a Docker volume from its `opts.json`, and for
a running container `kernel_mounts`: every entry of `/proc/<pid>/mountinfo`, its device and
root matched against the host's own table to every host path that shows that part of the
filesystem. They only add powers to those of the configuration; an entry at a point the
configuration does not list is judged as a declared one, except the runtime's own files (image
layers and snapshots, the volumes it manages, the container's own state directory with its hosts
file) when no host path of the entry is a source the configuration binds; a table that cannot be read, is empty, or lacks the host path of a directory or file the
configuration binds (swapped after the start, or the process chrooted away from it; a file
replaced since its mount still counts) is `kernel_unverified`, a power of its own) is reported as a `container` event with its name, image, runtime
and powers, on root's channel, unless a container with the same name, image, image digest and powers
was seen within the hour (4,096 remembered; a key is forgotten an hour after its last container
is gone, so the same container started again later is reported again), and its removal is
reported too. A start with the same name, tag and powers on another digest carries the digest it
replaces; the digest last seen for a key is kept however long the container was stopped,
for 4,096 keys, past which the one seen longest ago is forgotten and counted in the watcher's
issues. Docker and CRI-O report the digest; containerd and Podman bundles hold
none, and the alert says another image under the same tag is not told apart. The verifier raises the start under the snapshot rule's fingerprint and detail (the
medium "runs another image" for a replaced digest), so the next snapshot does not raise it again
and an acceptance holds for both; the detail, which an acceptance is bound to, holds the image
digest, so accepting a container never covers another image put under its tag, and leaves out
the container's ID and creation time, which go in the title, so an acceptance holds for the same
job container started every day.

Events go through bounded channels to a batcher: root's system paths have a channel of their own,
which the batcher reads first and no other account can fill (a loss there counts as root's), the
rest share one. The batcher sends at most every two seconds, in batches
under 176 KB (base64 in the envelope, under the verifier's 256 KB for an event), with the counts of what was lost (kernel queue overflow, full channel, full queue,
and among them the events on root's system paths) and whether a package manager was running, which is
known from a lock of dpkg, rpm or apk held by a process of root in `/proc/locks`, never from a
process name. If the transport cannot seal a batch because an earlier envelope is still pending,
the batcher keeps it in a queue of 4,096 events and retries with a backoff up to a minute. A
batch the verifier refuses for its size, which the transport drops from the chain, is not taken
for delivered: its events go again in batches half the size of the refused one, root's first,
down to a single event, which refused alone is counted as lost; the counts of lost events it
carried are kept for the next batch, and the bound doubles back with each batch that goes through. The
queue ranks events: root's system paths first; then the start-up files, `.ssh` and SSH keys in
the home of each account other than root, and the files in the cron and at spools owned by such
an account (by the file's UID, never its name: `crontab` writes temporary files with random
names; a removal takes the UID seen when the file appeared, and files gone before they could be
read share one quota), marked with the account (`owner`), 64 queued at most for each account, past which they count as noise; then everything else; then the upload noise no rule
raises an alert on. Batches take the ranks in that order, except that an event other than noise
that has waited 15 seconds goes right after root's; a full queue lets the lowest rank go first. When the sensor stops, what is queued is sent before
the stop event. Each snapshot carries the watchers' status.

The verifier stores the events (`events` table, seven days, at most 20,000 a host in 24 hours
for uploads and process starts, as many for the events marked with an account other than root
(2,000 for each account) and as many for root's system paths, past which they are counted, not
stored, but still judged within their batch) and judges each batch at once with the rules in
`internal/verifier/analyze/events.go`, looking up the same path's earlier events for what
appeared and disappeared within 15 minutes. Their alerts have kind `realtime` and, as changes,
are never resolved by a snapshot.

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

`InspectWithContainers` also reads the web servers of running containers. Each container's
filesystem is opened through `/proc/<pid>/root` (`collector.ContainerSource`), with the same
confinement as the host's and its `/proc` refused, since its magic links lead outside; the root
descriptor is released after the container is read, because the next container may get the same
PID. Paths in the configuration (roots, `alias`, logs, the files themselves) are translated
through the deepest of the container's bind mounts and named volumes; one inside the image has no
place on the host and is dropped, with an issue for a named site.

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
findings with signatures, or withdraws them if the file is an empty placeholder. Files in data
directories that are not scripts are searched for PHP that would run if they were included
(`code_in_data_file`, critical): after each real open tag (`<?php` or `<?` followed by a space
or a line break, or `<?=`), the block up to the `?>` that closes it as PHP's lexer reads it (not
one inside a string, a heredoc or nowdoc, or a block comment), or to the end, is matched against
the signatures, a list of dangerous calls and commands in backticks, without its comments and
with runs of blanks folded, block after block without overlap, so the cost stays linear. Binary
files (a PDF, an archive) hold an open tag every few megabytes by chance, and the random "code"
after it soon holds a backtick or a word like `exec(`: a block whose code holds, outside its
strings and comments, a control byte PHP 8 refuses to compile loses those two weak signals,
while the named signatures still count. A heredoc whose label is longer than the 128 bytes the lexer follows, or comes
after more than 16 blanks, is a signature of its own (`long_heredoc_label`): its body could
otherwise open a comment or close the block in front of the code after it. `__halt_compiler`
ends the block, since PHP compiles nothing after it: binary data appended to a payload cannot hide it. Code interpolated in a
string, a command or a heredoc (`{$...}`, `${...}`) is followed as code up to its matching
brace, with its own strings, so a quote or a `?>` inside it closes nothing (64 levels deep at
most; deeper is itself a finding, `nested_interpolation`). Whether short open tags are on is
php.ini's choice, so the content is lexed twice: once with the tags above, once with `<?`
opening a block whatever follows (but `xml`, and `php` glued to more text, which stops on the
undefined constant `php`, and a character no statement starts with, as in `<?>`). There a block
opened by a processing instruction (a lower-case target such as `mso-application` followed by
`?>`, `>` or a pseudo-attribute, which PHP 8 stops on as an undefined constant before anything
after it runs) counts only the named signatures; a keyword, `true`, `false`, `null` or a name
with upper case or an underscore, the shape of the constants PHP defines (`<?echo`, `<?const`,
`<?PHP_EOL>1;`), is code, and so is any name glued to the tag (`php` and `xml` included) after a
block PHP runs, which could have defined it; one opened by `<?` glued to anything else
(`<?$c=`, `<?@`, `<?(`, `<?PHP_EOL.`) is code, with the weak signals, a backtick counting only
when it interpolates a variable, and "=> {" or "[^", which PHP never compiles and the scripts a
cache holds are full of, make it uncompilable. In that second pass a block PHP 8 cannot compile makes the whole file
fail, so it is dropped unread and costs nothing of the budget. The
lexer (`phplex.go`) keeps its state from one piece of a file to the next: data files over 4 MB
are read through 1 MB at a time, within 4 GB a run, and code is judged with its block however far
from its tag; the code matched is bounded to 64 MB a run, since hostile code is matched at a few
megabytes a second. Past either budget an issue names the file, and the result's `code_search`
lists the files left unsearched (20 at most, then a count) with the five that spent the most code
and their owners: the verifier raises "Data files not searched for code" (high), so files stuffed
with code to hide a payload behind them point at themselves. The sensor remembers, in memory
and for 65,536 files at most, the data files a run searched to their end and found free of code,
by path, size, inode, modification and change time: later runs skip them while unchanged, so
a host with more documents than one run can search gets through them in a few runs instead of
stopping at the same ones every hour, and a file rewritten is searched again. Obfuscated function
names are found by one hand-written pass over each script, without regular expressions: chains
of quoted literals and `chr()` calls joined by `.` or `^` are decoded as PHP would and compared
with the names a webshell calls (decoders only next to an `eval`).

With `-state-dir`, the web collector writes a manifest of each application's code files
(`web-manifests/`, one quoted path and hash per line, in the walk's order) while it walks, and
compares it with the manifest in use as two sorted streams, so memory does not grow with the
application. The changes (`changes`, at most 200, `change_count`) go in the snapshot; the new
manifest replaces the old one only once that snapshot is delivered, like the log positions, so
a snapshot that is lost is compared again. A scan cut short keeps the old manifest; a manifest
that cannot be written (a full state directory, more than a million code files) is an issue
naming why, not a silent stop. Files too large to hash (or reached once the hash budget is spent)
are compared by their fingerprint of size, change time and inode when both runs have one, and
named as modified without a hash. Manifests no run has rewritten for seven days (an application
that is gone, a `.next` of a run that never finished) are removed. The scripts,
templates and SVG images among the changes are kept apart from the other changes in the diff, so
that changed files of other kinds cannot push them out, and read for a card skimmer
(`payment_skimmer`, critical): payment fields together with an exit to another host or with
obfuscation, or a live secret payment key. Field names hidden in `atob` literals (adjacent ones joined
with `+` decoded together), strings turned around with `split("").reverse().join("")`,
`String.fromCharCode` lists and runs of `\x`/`\u00` escapes are decoded first, and every string
literal is read as the browser builds it (escapes decoded, template literals without
substitutions, literals joined with `+`); names built through variables, aliases, arrays or
spread are past what a search without running the script can follow, a limit of the rule, and a file is read in 1 MB pieces with the families
gathered across them, so padding cannot separate the fields from the exit. When more than 50
scripts and templates changed at once, generated bundles (`pub/static`, `var/view_preprocessed`,
`wp-content/cache`) and packages with more than 10 changed scripts whose version file changed too (`style.css`,
`readme.txt`, the main plugin file, `composer.json`, `package.json`, `etc/module.xml`, `.info.yml`;
`plugins/<name>`, `vendor/<a>/<b>`, `app/code/<a>/<b>`...) are a deploy or an update and are
left out, named in the issues; a package whose scripts change by the dozen at the same version,
as decoys written next to a skimmer, is read; files changed elsewhere are still read. A harvest of every form field is reported with
them but is not enough alone: editor and file manager bundles hold it with exits and `eval`, and
on a corpus of WordPress, WooCommerce, its payment gateways, Elementor and Contact Form 7 that
combination matches dozens of admin bundles. The same corpus shows 31 Elementor admin bundles
holding payment field names with exits or obfuscation: read only when changed on their own. SVG images in upload
directories that run script are `active_svg_in_upload_dir`, critical when the script is hidden. Data directories
are read as a stream and not hashed; a code directory with more entries than the limit is
inspected the same way. Inside uploads, symlinks are reported and never followed; the only link
followed is an upload directory that is itself a link, and only towards the application, the
directory that holds its releases, or the directory holding the releases of any application found
on the host (a served copy linking its uploads to `deploy/shared`). That link is not a finding
when it leads to a directory there; one leading anywhere else, or named like a script, is. A
directory reached through links is listed and scanned once a run, served applications first: the
uploads every release of a deploy shares cost the budget once and are reported as the served
site's, and the real-time watch is given their real location. An index file in an upload, cache
or `wp-content` directory (plugins leave one to stop listings) does not make an application.

## Web server logs

`internal/weblog` does no I/O: it turns a line into a normalised request (combined format and
Caddy JSON, path decoded twice against double encoding) and applies the rules, with a bounded
per-IP state to correlate chains. The verifier will use the same code on raw logs.

At the end of a run the collector looks up the script each event names (`weblog.ScriptPath`) in
the sites that write the event's log (`discovery.Site.ScriptFiles`): every root of the nginx
site, both as root and as alias of its location, or Apache's `DocumentRoot` and the `Alias`
directives matching the request, so naming too many places can only make a file look present.
The answer (`on_disk`: `present`, `missing`, or empty) is left open for Caddy, a request its
location or a named fallback location may proxy, an Apache site with any proxy (`ProxyPass`,
`ProxyPassMatch`, a `RewriteRule` with the `P` flag) or an `AliasMatch`, a root with a variable
or relative, an event seen in more than one log, an error other than "does not exist",
or past 4,096 lookups a run. The verifier drops events for a missing script that did not
succeed (status outside 2xx), and adds to the detail when a requested script exists.

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
| `internal/collector/system` | accounts, SSH, sudoers, cron and at, systemd units, startup hooks, processes, sockets, package verification, privileged files, kernel (modules, taint, hidden processes, eBPF) |
| `internal/collector/web` | for each application: code hash tree, uploads, polyglots, webshell signatures, hidden files, reachable scripts |
| `internal/weblog` | access log parsing, attack rules, request redaction |
| `internal/collector/logs` | incremental, bounded log reading, events, statistics, committed positions |
| `internal/collector/apps` | application configuration and database: administrators, stored scripts, extensions, settings |
| `internal/watch` | real-time watchers: inotify on critical paths and the process connector on Linux, the container runtimes' state, batching |
| `internal/transport` | sealing, saving and sending envelopes from the sensor |
| `internal/verifier/pki` | private CA, server certificate, enrollment bundles |
| `internal/verifier/ingest` | mTLS ingest and chain verification |
| `internal/verifier/store` | SQLite store: hosts, snapshots, events, activity, alerts, users, sessions |
| `internal/verifier/analyze` | bounded snapshot decoding, rules on snapshots and on real-time events, sensor silence |
| `internal/verifier/notify` | alert emails |
| `internal/verifier/ui` | web interface |
| `internal/buildinfo` | version stamped at build time |

`deploy/verifier` holds the verifier's Dockerfile and `docker-compose.yml`, `deploy/systemd` the
sensor's unit. Planned: a Kubernetes DaemonSet.
