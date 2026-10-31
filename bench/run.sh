#!/bin/bash
# Detection benchmark: builds the reference host from the committed sources, runs every scenario
# in a fresh container and writes the raw results (results.tsv, versions.tsv), the report
# (RESULTS.md), the chart (detection.svg) and the benchmark section of README.md.
#
#   bench/run.sh            all scenarios, 4 at a time
#   JOBS=8 bench/run.sh     more parallel containers
#   RENDER_ONLY=1 bench/run.sh   redraw the report and the chart from the saved results
#
# Process events need a kernel with the process connector (CONFIG_PROC_EVENTS) and the initial
# network namespace: BENCH_DOCKER_FLAGS=--network=host on a Linux host. Without them the
# scenarios that only a process start reveals are reported as missed.
set -euo pipefail

cd "$(dirname "$0")/.."
readonly image=tripwatch-bench
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -z "${RENDER_ONLY:-}" ]; then
commit=$(git rev-parse --short HEAD)
arch=$(docker version --format '{{.Server.Arch}}')
mkdir -p "$work/src" "$work/ctx"
git archive HEAD | tar -x -C "$work/src"
(cd "$work/src" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$work/ctx/tripwatch-sensor" ./cmd/tripwatch-sensor \
  && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o "$work/ctx/judge" ./bench/judge)
cp -R bench/Dockerfile bench/probe.sh bench/refs.sh bench/fixture bench/scenarios "$work/ctx/"
docker build -q -t "$image" "$work/ctx" >/dev/null

docker run --rm "$image" sh -c '
  echo "commit	'"$commit"'"
  echo "arch	'"$arch"'"
  echo "aide	$(aide -v 2>&1 | sed -n "s/^AIDE \([0-9.]*\).*/\1/p" | head -n1)"
  echo "rkhunter	$(dpkg-query -W -f="\${Version}" rkhunter)"
  echo "debsums	$(dpkg-query -W -f="\${Version}" debsums)"
  echo "os	$(. /etc/os-release && echo "$PRETTY_NAME")"
  echo "kernel	$(uname -r)"
' >bench/versions.tsv

ls bench/scenarios/*.sh | xargs -n1 basename | xargs -P "${JOBS:-4}" -I{} \
  docker run --rm --cap-add LINUX_IMMUTABLE --cap-add NET_ADMIN ${BENCH_DOCKER_FLAGS:-} "$image" /bench/probe.sh run /bench/scenarios/{} \
  | sort >bench/results.tsv
fi

commit=$(sed -n 's/^commit\t//p' bench/versions.tsv)
arch=$(sed -n 's/^arch\t//p' bench/versions.tsv)
bench/render.sh bench/results.tsv bench/versions.tsv "$commit" "$arch" "$work/summary.md" >bench/RESULTS.md

if grep -q '<!-- bench:start -->' README.md; then
  awk -v summary="$work/summary.md" '
    /<!-- bench:start -->/ { print; while ((getline line < summary) > 0) print line; skip = 1; next }
    /<!-- bench:end -->/ { skip = 0 }
    !skip
  ' README.md >"$work/README.md"
  cp "$work/README.md" README.md
else
  echo "bench: README.md has no benchmark section; summary not inserted" >&2
fi

echo "bench: results for $commit in bench/RESULTS.md"
