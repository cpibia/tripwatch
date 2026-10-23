# Changelog

All notable changes to tripwatch. Each release lists what changes for the sensor and for the
verifier, so it is clear which of the two needs updating. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0 a minor version may change behaviour.

## [Unreleased]

## [0.1.11] - 2026-10-23

False positives seen on a real server, fixed. Update the verifier, then the sensors
(`tripwatch-sensor -update`): some fixes need both. Alerts already open from the earlier rules
stay open until closed by hand.

### Sensor

- Only private executable mappings are reported: shared ones are what OPcache's JIT and other
  JITs map, a shared anonymous region showing as `/dev/zero (deleted)`.
- A process whose deleted executable has been replaced by a new file at the same path is marked
  as such (`exe_replaced`): a package upgrade it was not restarted for.
- A program or script run by an account from its own home is no longer reported as started from
  an unusual place (a crontab calling a script in the deploy user's home); the same file run by
  another account, by root or by the web server's user still is.
- The packages collector fingerprints dpkg's list of installed versions apart from the
  checksums (`status_sha256`).
- A web server's configuration counts as stale only if it changed after the server last read it:
  a reload starts new workers while the master keeps running.

### Verifier

- A process still running a replaced binary in the system's directories is a low "restart
  pending"; one whose binary is gone stays high. Shared anonymous regions reported by older
  sensors are ignored.
- "Package database changed without installations" no longer follows every upgrade: with
  sensors from 0.1.11 on dpkg hosts, an upgrade (the installed versions changed) raises
  nothing, and checksums or file lists changed while no version did raise a high "Package
  checksums changed without installations".
- Real-time events in systemd's directories count only for files systemd loads (units,
  drop-ins, generators): the temporary names of atomic writes no longer raise alerts, and
  removing a service or a scheduled task raises none. Uninspected process starts are low.
- A new generator or set-user-ID program in the system's directories is medium, not high, when
  packages were installed or upgraded since the previous snapshot.
- A script requested in an upload directory and answered with a redirect is low: the redirect
  is the server's own (to https, to a canonical host) and the request that follows is judged on
  its own status. Any other status but success stays high.

## [0.1.10] - 2026-10-23

Update the verifier; the sensors stay on 0.1.9.

### Verifier

- Each sensor start is judged against how the previous run ended, from the system boot it
  reports: a new boot after a clean stop is one low "Server was off" event, a new version on the
  same boot a low "Sensor updated", a new boot without a clean stop a medium "Server restarted
  without a clean stop"; the same boot and version, a service restarted by hand, stays a high
  "Sensor restarted without a reboot". A plain stop raises nothing by itself, and the silence
  that follows it is medium for a day, then high. A server switched off every night no longer
  raises three alerts a day. Starts seen before this version are read back from their alerts.

## [0.1.9] - 2026-10-23

Update the verifier first, then the sensors (`tripwatch-sensor -update`): a verifier older than
this ignores the real-time events and the new collectors. The sensor's systemd unit gains
`CAP_NET_ADMIN`, which the packages install with the new unit; a unit copied by hand has to be
replaced. The first snapshot after the update runs the new rules on what is already there:
modules built outside the kernel's tree, packet sockets of monitoring agents and native modules
mapped from web roots show up then, and can be accepted once.

### Sensor

- **Real-time events.** Between snapshots the sensor watches with inotify the account
  databases, sudo, polkit and doas, the SSH server configuration and every account's
  `authorized_keys`, cron and `at`, systemd units and generators, library preloading, start-up
  scripts and the upload directories of the web applications, and sends each change within two
  seconds with the file's size, SHA-256, owner and mode. From the kernel's process connector it
  reports only the process starts that matter: the web server's user starting a shell, an
  interpreter or a network tool; programs and scripts run from `/tmp`, `/dev/shm`, homes and web
  roots; programs deleted after they started; root gained through a set-user-ID program outside
  the system's directories.
- Events travel in signed event envelopes of the same chain, in bounded batches with the count
  of what was lost and whether a package manager was running; they wait in a bounded queue while
  the verifier is unreachable. Each snapshot says whether the watchers run, and why not.
- `tripwatch-sensor -watch-only` prints what the watchers report, without a verifier.
- Hardening of the watchers after a security review: a link in a watched directory is never
  followed, and no device is ever opened while reading file attributes (`O_NOCTTY` everywhere,
  attributes read only from regular files and directories), so a terminal planted by the web
  server's user can no longer become the sensor's controlling terminal; hashing is bounded to
  files up to 1 MB and 16 MB a second, with a budget of its own for root's files; a package manager is recognised by a lock only root can
  hold, not by a process name; upload noise is dropped before system events when the queue is
  full; what is queued at a stop is sent before the stop event; directories left unwatched by
  the bounds are reported; `CAP_NET_ADMIN` is given up right after subscribing to process
  events.
- A new `kernel` collector: modules from both of the kernel's lists with their place in the
  module tree, taint and lockdown, processes hidden from `/proc`'s listing (every PID the kernel
  may have handed out is probed, within ten seconds), eBPF programs held by processes, pinned
  BPF objects and dynamic kprobes.
- The `sockets` collector also reports packet (`AF_PACKET`) and raw sockets, with the
  executable of the process that holds each.
- The `processes` collector reports the process tracing each one with ptrace and the
  executable mappings of memory-only files, of files under scratch directories, homes and web
  roots, and of files deleted outside the system's library directories.
- A sensor that stops sends a last signed event saying so, and whether its package is being
  removed: the package's pre-removal script leaves a marker the running sensor reads.

### Verifier

- Events are kept for seven days, at most 20,000 a server in 24 hours for what the web server's
  user can produce and as many again for system paths, and judged at once (events over the
  quota still count for the rules within their batch).
  Critical: the web server's user starting a shell or a network tool, root gained through an
  unknown set-user-ID program, changes to sudo or polkit rules and to `ld.so.preload`, and what
  no hourly snapshot would show: a script appearing in the uploads and gone within 15 minutes,
  an SSH key file written and removed or changed and put back. High: scripts and `.htaccess`
  files in upload directories, SSH keys and server settings, services, scheduled tasks,
  start-up scripts, programs run from unusual places or deleted after start. Changes to
  services, scheduled tasks and start-up scripts made while a package manager runs are one
  severity lower. Lost events are an alert of their own, high when system events were among
  them. A file's content is part of an alert's fingerprint, so an acknowledged alert does not
  absorb a later, different change to the same file.
- Each server's page lists its latest events, and its System block says whether files and
  processes are watched.
- Kernel rules: a module hidden from either list, a process hidden from `/proc` and an eBPF
  tracing program held by a program from an unusual place or a deleted one are critical; a
  module outside the module tree, a module loaded with out-of-tree or unsigned taint, new taint
  flags of that kind and new kprobes are high; new eBPF programs and pins are medium.
- A packet or raw socket held by a program from an unusual place or deleted is critical, by a
  program other than the known capture and network tools high, by no listed process medium.
- Fileless processes (run from `memfd`) and code mapped from memory-only files or scratch
  directories are critical, code mapped from homes, web roots or deleted files high. A process
  traced by something other than a known debugger is high, critical when it is sshd, su, sudo
  or another holder of secrets, or when the tracer is unknown or out of place.
- "Sensor removed" (high) when the sensor package is uninstalled, "Sensor stopped" (medium)
  when the service stops, by hand or for a reboot.
- The benchmark runs the sensor's watchers during each scenario and judges what they report with
  the verifier's rules.

## [0.1.8] - 2026-10-23

Update the verifier first, then the sensors (`tripwatch-sensor -update`).

### Sensor

- Each snapshot carries the machine's system: distribution and version (`/etc/os-release`),
  kernel, architecture, hostname, boot time, CPUs, memory, the addresses of its network
  interfaces (loopback and link-local left out) and the sensor's version. Values are bounded:
  they come from files the host writes.

### Verifier

- A **Servers** page lists the fleet: system and kernel, sensor version flagged "update
  available" when older than the verifier (with `tripwatch-sensor -update`), addresses, web
  applications, last heartbeat and snapshot, alerts; revoked servers apart. A sensor that does
  not send its system yet still shows its version, read from the signed event of its start.
- Each server's page has a System block: the facts above plus package manager and count,
  listening ports and web applications. The overview's server cells show the sensor version.

## [0.1.7] - 2026-10-23

Update the verifier; the sensors stay on 0.1.5.

### Verifier

- A script in an upload directory is critical when its content carries a webshell signature,
  and high when it carries none: some applications keep generated templates there. The alert's
  detail is unchanged, so acceptances given before keep holding; an accepted file that changes
  is raised again.
- Beyond the cap of 100 open alerts per rule on a server, the rest is held in an aggregate
  ("Many alerts of the same rule"). That aggregate now joins its group, which says
  "+ more held back"; accepting or resolving the group closes it too, and the alerts it held are
  raised one by one with the next snapshot instead of seeming to come back.

## [0.1.6] - 2026-10-23

Update the verifier; the sensors stay on 0.1.5.

### Verifier

- Revoked servers no longer count in the overview: they are left out of the figures, the charts,
  the server cells, the healthy count and the alarm mark, and named apart under Servers. Their
  pages keep their alerts as a record.
- Every row of Top rules and Web attacks opens the latest alert it comes from. Web attacks count
  the requests each alert reports rather than how often the alert was seen, and read the source
  address of alerts raised before 0.1.3, whose detail is in Italian.

## [0.1.5] - 2026-10-23

Update the verifier and the sensors.

### Sensor

- rpm hosts are verified like dpkg and apk ones: the sensor reads the rpm database directly,
  Berkeley DB (RHEL/CentOS 7 and 8, Amazon Linux 2) or SQLite (RHEL 9, Amazon Linux 2023,
  Fedora, including transactions still in the write-ahead log), and reports system files that no
  longer match their package. Files rpm itself leaves out of verification (`%ghost`,
  `%verify(not md5)`, languages and documentation not installed) are skipped. Until now every
  dot-file under `/usr` on these hosts (`.hmac` checksums of crypto libraries, `.build-id`,
  manual pages) was a "Hidden entry in /usr" alert, because no package database was read.
- Hidden entries under `/usr` are no longer searched in source trees (`/usr/src`,
  `/usr/local/src`) and language package trees (`node_modules`, `site-packages`,
  `dist-packages`), where checkouts and packages ship `.git`, `.github` and CI files. Unowned
  subdirectories of a packaged hidden directory (rpm lists the `.build-id` links, not the
  directories holding them) are walked instead of reported; files added there still are.
- An upload directory that is a link to a directory inside the application or its deploy
  directory (`releases/5/uploads -> ../../shared/uploads`) is no longer a "Suspicious link": it
  is the usual layout of release-based deploys, and its content is still scanned. A link leading
  anywhere else, or named like a script, is still reported.

### Verifier

- The overview is an operations dashboard, dark slate by default (light and system themes stay
  in the menu):
  - a strip of figures for open critical, high, medium and low alerts and silent sensors, each
    with what arrived in the last 24 hours, the age of the oldest and the last 7 days' trend;
  - alerts raised over the last 24 hours or 7 days, in columns stacked by severity;
  - the servers as cells with their worst alert, heartbeat and snapshot, silent ones hatched;
  - open alerts grouped by rule across servers, the first 10 groups with a link to the rest;
  - top rules of the last 7 days, unresolved alerts by server, and the sources and targets of
    the attacks seen in the web server logs.

  Every figure comes from the alerts and hosts the verifier holds; charts are SVG drawn by the
  server, with no script. The side panel stays on the Alerts page.
- Closed groups of alerts stayed open on narrow screens; they now stay closed.

## [0.1.4] - 2026-10-23

Update the verifier and the sensors.

### Sensor

- `sudo tripwatch-sensor -update` installs the latest release in the same form as the installed
  one (`.deb`, `.rpm` or static binary) for the server's architecture, after checking it against
  the release's `SHA256SUMS`, and restarts the service. Nothing changes if the running version is
  already the latest.

### Releases

- The sensor's packages and binaries are also published under fixed names
  (`tripwatch-sensor_amd64.deb`, `tripwatch-sensor.x86_64.rpm`, `tripwatch-sensor_linux_amd64` and
  the arm64 equivalents), so `releases/latest/download/` always gives the newest one and the
  install commands in the README no longer name a version.

### Verifier

- Interface redesign in the same control-room direction, after a design review:
  - IBM Plex Sans and Mono embedded in the binary, one type scale, section titles above body
    text, clearer button hierarchy;
  - the overview's rows carry no buttons; actions live in the side panel and on each alert's
    page, where Acknowledge is the primary action, and in long lists they show on the row being
    pointed at;
  - "Accept as legitimate" only on an alert's page, with what it does, or for a whole group;
  - resolving or accepting a group of critical or high alerts asks once more with their number;
  - each row of a group shows the file or item that tells it apart;
  - the side panel puts a silent sensor and planted web code ahead of other alerts of the same
    severity, and comes before the tables on smaller screens;
  - new mark, a tripwire cut in the middle, in ink; the wire and the browser tab icon turn red
    while a critical alert is open;
  - email not configured shows as a warning in the menu; the running version is shown;
  - contrast of red and muted text raised above 4.5:1 in both themes, larger touch targets.

## [0.1.3] - 2026-10-23

Update the verifier; the sensors stay on 0.1.2.

### Verifier

- The interface, the alerts and the emails are in English. Alerts raised by earlier versions
  keep their Italian text until the condition is raised again; conditions whose fingerprint
  carried an Italian description of a file's owner and mode are raised once more under the
  English one, and an acceptance of such an alert has to be given again.

- Every alert page has **Copy for an AI assistant**: the alert in Markdown (what tripwatch is,
  the alert's facts, the collected detail fenced as data, and the question to answer), ready to
  paste into an AI chat.
- A privilege policy file or directory writable by someone other than root is explained in plain
  words: who can write it (every user, a named group and its members, an account, an ACL), why
  that gives root, and the usual fix. The raw owner and mode close the text.

## [0.1.2] - 2026-10-23

Update both the verifier and the sensors.

### Sensor

- Hidden scripts that libraries ship on purpose are no longer reported as hidden: the
  `.php_cs.php` and `.php_cs.dist.php` tool configurations, and hidden files inside the test
  directories of a dependency (`vendor/`, `node_modules/`, `bower_components/`, under `tests/`,
  `test/`, `fixtures/`). Webshell signatures are still searched in them.

### Verifier

- **Accept** an alert, or a whole group, as legitimate. A resolved alert whose condition is still
  present comes back with the next snapshot; an accepted one is not raised again while its
  evidence (for a file, its size and SHA-256; for a process, its executable and hash) stays the
  same, and comes back as soon as it changes. The server's page lists what was accepted and puts
  it back under watch. Silences, broken chains, sensor events and the verifier's own alerts
  cannot be accepted.

### Documentation

- The verifier's compose defaults to the `latest` image; pinning a release is documented as the
  way to decide when to update.

## [0.1.1] - 2026-10-23

Update both the verifier and the sensors.

### Sensor

- Hidden entries under `/usr` that a package installed (kernel headers, `.build-id`
  directories) are no longer reported. Anything added inside such a packaged hidden directory
  still is. Alerts already raised for them stay open until resolved by hand.

### Verifier

- Alerts of the same rule, host and severity are one row that opens onto them, with actions
  that acknowledge or resolve the whole group. An open group stays open across the automatic
  refresh.
- The enrollment page asks for the server's system (Debian/Ubuntu, RHEL family, or sensor
  already installed) and gives one command that downloads the sensor package of the verifier's
  own release for the server's architecture, installs it, removes the download, enrolls the
  server and starts the sensor.
- The enrollment command uses `sudo`.

### Documentation

- README with a table of contents, a dedicated installation section, and how to learn about new
  releases, check installed versions, update and remove.

## [0.1.0] - 2026-10-23

First public release.

- Sensor as `.deb` and `.rpm` packages for amd64 and arm64, and as static binaries.
- Verifier as a multi-arch container image on GHCR, with its `docker-compose.yml` and
  `verifier.env.example` attached to the release.
- Build provenance attestations for every file and for the image.

[Unreleased]: https://github.com/cpibia/tripwatch/compare/v0.1.11...HEAD
[0.1.11]: https://github.com/cpibia/tripwatch/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/cpibia/tripwatch/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/cpibia/tripwatch/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/cpibia/tripwatch/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/cpibia/tripwatch/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/cpibia/tripwatch/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/cpibia/tripwatch/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/cpibia/tripwatch/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/cpibia/tripwatch/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cpibia/tripwatch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cpibia/tripwatch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cpibia/tripwatch/releases/tag/v0.1.0
