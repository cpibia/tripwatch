# Changelog

All notable changes to tripwatch. Each release lists what changes for the sensor and for the
verifier, so it is clear which of the two needs updating. Versions follow
[Semantic Versioning](https://semver.org/); before 1.0 a minor version may change behaviour.

## [Unreleased]

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

[Unreleased]: https://github.com/cpibia/tripwatch/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/cpibia/tripwatch/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/cpibia/tripwatch/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cpibia/tripwatch/releases/tag/v0.1.0
