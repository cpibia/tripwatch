# Changelog

All notable changes to tripwatch. Each release lists what changes for the sensor and for the
verifier, so it is clear which of the two needs updating. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0 a minor version may change behaviour.

## [Unreleased]

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

[Unreleased]: https://github.com/cpibia/tripwatch/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/cpibia/tripwatch/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/cpibia/tripwatch/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/cpibia/tripwatch/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/cpibia/tripwatch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cpibia/tripwatch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cpibia/tripwatch/releases/tag/v0.1.0
