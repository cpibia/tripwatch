#!/bin/bash
# Runs inside the benchmark container.
#   probe.sh baseline         record every tool's output on the clean system
#   probe.sh run <scenario>   apply the scenario, run every tool, print one result line
#
# A tool detects a scenario when the lines of its output that mention one of the scenario's indicators
# differ from the same lines on the clean system: something new appeared or something known
# changed. For tripwatch the "lines" are the JSON objects that hold the indicator: in its snapshot,
# and in the alerts the verifier's real-time rules raise on what its watchers saw while the
# scenario ran.
set -u

readonly TOOLS=(tripwatch aide rkhunter debsums)
readonly BEFORE=/bench/before
readonly AFTER=/bench/after
readonly TOOL_TIMEOUT=900
readonly EVENTS=/bench/events.jsonl

run_tool() {
  local tool=$1 out=$2
  case $tool in
    tripwatch)
      # The state kept from the baseline, as on a server: log positions and code manifests.
      tripwatch-sensor -app-db=false -state-dir=/bench/state >"$out" 2>/dev/null
      if [ -f "$EVENTS" ]; then judge <"$EVENTS" >>"$out"; fi
      ;;
    aide) aide --config=/etc/aide/aide.conf --check >"$out" 2>/dev/null ;;
    rkhunter)
      rkhunter --check --sk --nocolors --logfile "$out.log" >/dev/null 2>&1
      sed -E 's/^\[[0-9:]+\] //' "$out.log" >"$out"
      ;;
    debsums) debsums -ac >"$out" 2>/dev/null ;;
  esac
}

export -f run_tool
export EVENTS

# measure runs a tool under a timeout and records "status seconds max_rss_kb".
measure() {
  local tool=$1 dir=$2 status
  timeout "$TOOL_TIMEOUT" /usr/bin/time -f '%e %M' -o "$dir/$tool.time" \
    bash -c "run_tool $tool $dir/$tool.out"
  status=$?
  if [ "$status" -eq 124 ]; then
    echo "blocked - -" >"$dir/$tool.stat"
  else
    # time prepends a line when the command exits non-zero, as AIDE does when it finds changes.
    echo "done $(tail -n1 "$dir/$tool.time")" >"$dir/$tool.stat"
  fi
}

mentions() {
  local tool=$1 file=$2 indicators=$3 indicator
  while IFS= read -r indicator; do
    mention "$tool" "$file" "$indicator"
  done <<<"$indicators"
}

mention() {
  local tool=$1 file=$2 indicator=$3
  if [ "$tool" = tripwatch ]; then
    jq -c --arg i "$indicator" '
      .. | select(type == "object" or type == "array")
         | select(any(.[]; type == "string" and contains($i)))' "$file" 2>/dev/null | sort
  else
    grep -F -- "$indicator" "$file" | sort
  fi
}

verdict() {
  local tool=$1 indicator=$2 state
  read -r state _ <"$AFTER/$tool.stat"
  if [ "$state" = blocked ]; then
    echo blocked
  elif cmp -s <(mentions "$tool" "$BEFORE/$tool.out" "$indicator") \
              <(mentions "$tool" "$AFTER/$tool.out" "$indicator"); then
    echo no
  else
    echo yes
  fi
}

baseline() {
  # aideinit drops capabilities with capsh, which a container build does not allow.
  aide --config=/etc/aide/aide.conf --init >/dev/null 2>&1
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  rkhunter --propupd --nocolors >/dev/null 2>&1
  mkdir -p "$BEFORE"
  for tool in "${TOOLS[@]}"; do
    measure "$tool" "$BEFORE"
  done
}

run() {
  local scenario=$1 indicator line
  indicator=$(sed -n 's/^# indicator: //p' "$scenario")
  # The watchers run as in daemon mode, placed after a first snapshot: what the scenario does in
  # between two snapshots is what they are for.
  tripwatch-sensor -watch-only -app-db=false -state-dir= >"$EVENTS" 2>/bench/watch.log &
  local watcher=$! i
  for i in $(seq 100); do
    grep -q '"msg":"watching"' /bench/watch.log && break
    sleep 0.2
  done
  bash "$scenario" >/dev/null 2>&1
  # Batches leave at most two seconds apart.
  sleep 3
  kill -INT "$watcher"
  wait "$watcher"
  mkdir -p "$AFTER"
  line=$(basename "$scenario" .sh)
  for tool in "${TOOLS[@]}"; do
    measure "$tool" "$AFTER"
    line+=$'\t'"$(verdict "$tool" "$indicator")"
  done
  for tool in "${TOOLS[@]}"; do
    read -r _ seconds rss <"$AFTER/$tool.stat"
    line+=$'\t'"$seconds"$'\t'"$rss"
  done
  echo "$line"
}

case ${1:-} in
  baseline) baseline ;;
  run) run "$2" ;;
  *) echo "usage: probe.sh baseline | run <scenario>" >&2; exit 2 ;;
esac
