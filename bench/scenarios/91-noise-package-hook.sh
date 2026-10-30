# category: noise
# title: Installation of a package that ships a login hook
# indicator: /etc/profile.d/demo-env.sh
d=$(mktemp -d)
mkdir -p "$d/DEBIAN" "$d/etc/profile.d" "$d/usr/share/demo-env"
printf 'Package: demo-env\nVersion: 1.0\nArchitecture: all\nMaintainer: bench <bench@example.com>\nDescription: environment for a demo tool\n' >"$d/DEBIAN/control"
printf 'export DEMO_HOME=/usr/share/demo-env\n' >"$d/etc/profile.d/demo-env.sh"
printf 'demo\n' >"$d/usr/share/demo-env/README"
dpkg-deb --build "$d" /tmp/demo-env.deb >/dev/null
dpkg -i /tmp/demo-env.deb >/dev/null
rm -rf "$d" /tmp/demo-env.deb
