#!/bin/bash
# Writes the content references of the bench's public plugin, as WordPress.org's plugin-checksums
# lists them, for the judge to serve locally: release 1.0.0 as installed, and 1.1.0 as the plugin
# update scenario makes it, applied to a copy.
set -euo pipefail

readonly plugin=/var/www/wp/wp-content/plugins/demo-gallery
readonly out=/bench/refs/plugin-checksums/demo-gallery

checksums() {
  (cd "$1" && find . -type f | sed 's#^\./##' | sort | while IFS= read -r f; do
    printf '%s\t%s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"
  done) | jq -R -s 'split("\n") | map(select(length > 0) | split("\t")) | map({key: .[0], value: {sha256: .[1]}}) | from_entries | {files: .}'
}

mkdir -p "$out"
checksums "$plugin" >"$out/1.0.0.json"
copy=$(mktemp -d)
cp -a "$plugin/." "$copy/"
sed "s#$plugin#$copy#g" /bench/scenarios/90-noise-plugin-update.sh | bash
checksums "$copy" >"$out/1.1.0.json"
rm -rf "$copy"
