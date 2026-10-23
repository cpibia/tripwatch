# Security policy

tripwatch runs as root on the servers it monitors and holds the certificate authority of every
enrolled host, so vulnerabilities in it matter.

## Reporting a vulnerability

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a
vulnerability**. Please do not open a public issue. Include the affected version or commit, the
component (sensor, verifier, transport, packaging) and, if you can, the steps to reproduce.

Fixes are released as a new version, and the advisory is published once a fixed release is
available.

## Supported versions

Only the latest release receives security fixes.

## Scope

The trust model and its known limits are described in the README: an attacker who already has
root on a monitored server can stop or impersonate that server's sensor, and that alone is not a
vulnerability. Ways to do it without root, to make the verifier accept forged or replayed data,
or to make the sensor read or execute something it should not, are in scope.
