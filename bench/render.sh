#!/bin/bash
# Renders the benchmark results as Markdown.
#   render.sh <results.tsv> <versions.tsv> <commit> <arch> <summary-out>
# The full report goes to stdout, the README section to <summary-out> and the chart to
# bench/detection.svg.
set -euo pipefail

results=$1 versions=$2 commit=$3 arch=$4 summary=$5
scenarios=$(dirname "$0")/scenarios

joined=$(mktemp)
trap 'rm -f "$joined"' EXIT
sort "$results" | while IFS=$'\t' read -r id rest; do
  file="$scenarios/$id.sh"
  printf '%s\t%s\t%s\t%s\n' "$id" "$(sed -n 's/^# category: //p' "$file")" \
    "$(sed -n 's/^# title: //p' "$file")" "$rest"
done >"$joined"

awk -F'\t' -v svg="$(dirname "$0")/detection.svg" -v commit="$commit" -v arch="$arch" -v versions="$versions" -v summary="$summary" -v day="$(date +%Y-%m-%d)" '
function cell(v) { return v == "yes" ? "✅" : (v == "blocked" ? "⛔ blocked" : "❌") }
function mb(kb) { return kb == "-" ? "-" : sprintf("%.0f MB", kb / 1024) }
function secs(s) { return s == "-" ? "over 900 s" : sprintf("%.1f s", s) }
# chart draws one horizontal bar per tool on a track as long as the scenario count. The colors
# follow the light and dark surfaces of the page that shows it.
function chart(file, n, commit, os,    t, y, w, track, left) {
  left = 132; track = 460
  print "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"720\" height=\"300\" viewBox=\"0 0 720 300\" role=\"img\" aria-labelledby=\"title desc\">" > file
  print "<title id=\"title\">Attack scenarios detected out of " n "</title>" > file
  printf "<desc id=\"desc\">tripwatch %d, AIDE %d, rkhunter %d, debsums %d out of %d scenarios.</desc>\n", total[1], total[2], total[3], total[4], n > file
  print "<style>" > file
  print "svg { --surface: #fcfcfb; --track: #ebeae6; --bar: #2a78d6; --text: #0b0b0b; --muted: #52514e; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; }" > file
  print "@media (prefers-color-scheme: dark) { svg { --surface: #1a1a19; --track: #2e2e2c; --bar: #3987e5; --text: #f0efec; --muted: #c3c2b7; } }" > file
  print ".surface { fill: var(--surface); } .track { fill: var(--track); } .bar { fill: var(--bar); }" > file
  print ".title { fill: var(--text); font-size: 17px; font-weight: 600; } .sub, .foot { fill: var(--muted); font-size: 13px; }" > file
  print ".name { fill: var(--text); font-size: 15px; } .value { fill: var(--text); font-size: 15px; font-weight: 600; font-variant-numeric: tabular-nums; } .foot { font-size: 12px; }" > file
  print "</style>" > file
  print "<rect class=\"surface\" width=\"720\" height=\"300\" rx=\"12\"/>" > file
  print "<text class=\"title\" x=\"28\" y=\"42\">Attack scenarios detected out of " n "</text>" > file
  print "<text class=\"sub\" x=\"28\" y=\"64\">Same Debian host for every tool, each with its default configuration</text>" > file
  for (t = 1; t <= ntools; t++) {
    y = 96 + (t - 1) * 44
    w = int(track * total[t] / n + 0.5)
    printf "<text class=\"name\" x=\"28\" y=\"%d\">%s</text>\n", y + 14, tool[t] > file
    printf "<rect class=\"track\" x=\"%d\" y=\"%d\" width=\"%d\" height=\"18\" rx=\"4\"/>\n", left, y, track > file
    if (w > 0) {
      printf "<rect class=\"bar\" x=\"%d\" y=\"%d\" width=\"%d\" height=\"18\" rx=\"4\"/>\n", left, y, w > file
      printf "<rect class=\"bar\" x=\"%d\" y=\"%d\" width=\"%d\" height=\"18\"/>\n", left, y, (w < 4 ? w : 4) > file
    }
    printf "<text class=\"value\" x=\"%d\" y=\"%d\">%d of %d</text>\n", left + track + 14, y + 14, total[t], n > file
  }
  printf "<text class=\"foot\" x=\"28\" y=\"280\">Commit %s, %s. Method and per-scenario detail in bench/RESULTS.md</text>\n", commit, os > file
  print "</svg>" > file
  close(file)
}
BEGIN {
  ntools = split("tripwatch AIDE rkhunter debsums", tool, " ")
  ncat = split("persistence privilege integrity runtime web limits", order, " ")
  label["persistence"] = "Persistence"
  label["privilege"] = "Privileges"
  label["integrity"] = "System integrity"
  label["runtime"] = "Processes and network"
  label["web"] = "Web applications"
  label["limits"] = "Limits: attacks between two checks, and traps"
  while ((getline line < versions) > 0) { split(line, kv, "\t"); version[kv[1]] = kv[2] }
}
{
  id = $1; cat = $2
  if (cat == "control") {
    for (t = 1; t <= ntools; t++) { control[t] = $(3 + t); cost_s[t] = $(6 + 2 * t); cost_m[t] = $(7 + 2 * t) }
    next
  }
  n++; catcount[cat]++
  row[n] = "| " $3 " |"
  rowcat[n] = cat
  for (t = 1; t <= ntools; t++) {
    v = $(3 + t)
    row[n] = row[n] " " cell(v) " |"
    if (v == "yes") { total[t]++; bycat[cat, t]++ }
  }
}
END {
  fp = ""
  for (t = 1; t <= ntools; t++) if (control[t] == "yes") fp = fp " " tool[t]

  print "# Detection benchmark"
  print ""
  printf "Commit `%s`, %s, container %s on %s, kernel %s. Tools compared: AIDE %s, rkhunter %s, debsums %s,\n", commit, day, version["os"], arch, (version["kernel"] == "" ? "not recorded" : version["kernel"]), version["aide"], version["rkhunter"], version["debsums"]
  print "with the default configuration of their Debian packages. Regenerate with `bench/run.sh`."
  print ""
  print "## Method"
  print ""
  print "Every scenario starts from a clean container, the same for all: a Debian host with a WordPress site, on"
  print "which every tool has already taken its baseline. The scenario applies the attack, then every tool runs"
  print "once. A tool **detects** the scenario when the lines of its output that mention the artifact of the"
  print "attack (a path, the comment of a key, a port) differ from those of the baseline: something new appeared"
  print "or something known changed. For tripwatch the JSON objects that contain the artifact are compared: those"
  print "of the snapshot, where the final judgement belongs to the verifier and we measure whether the data"
  print "arrives, and the alerts the real-time rules of the verifier raise on what the watchers of the sensor reported while"
  print "the scenario ran, the watchers being started after a first snapshot as in daemon mode. Process events"
  print "need a kernel with the process connector: the run says which kernel it had."
  print "**Blocked** means the tool did not finish within 900 s."
  print ""
  if (fp == "") print "The control scenario, with no attack, produces no differences for any tool."
  else print "Warning: the control scenario, with no attack, produces differences for:" fp "."
  print ""
  print "## Results per scenario"
  print ""
  for (c = 1; c <= ncat; c++) {
    cat = order[c]
    if (!catcount[cat]) continue
    print "### " label[cat]
    print ""
    print "| Scenario | tripwatch | AIDE | rkhunter | debsums |"
    print "|---|:-:|:-:|:-:|:-:|"
    for (i = 1; i <= n; i++) if (rowcat[i] == cat) print row[i]
    print ""
  }
  print "## Cost of a full check"
  print ""
  print "Measured on the control scenario, in the same container."
  print ""
  print "| Tool | Time | Peak memory |"
  print "|---|--:|--:|"
  for (t = 1; t <= ntools; t++) printf "| %s | %s | %s |\n", tool[t], secs(cost_s[t]), mb(cost_m[t])

  print "Across " n " attack scenarios reproduced in a Debian container (commit `" commit "`), how many each" > summary
  print "tool detects with its default configuration:" > summary
  print "" > summary
  print "![Scenarios detected out of " n ": tripwatch " total[1] ", AIDE " total[2] ", rkhunter " total[3] ", debsums " total[4] "](bench/detection.svg)" > summary
  print "" > summary

  chart(svg, n, commit, version["os"])
  print "| Category | Scenarios | tripwatch | AIDE | rkhunter | debsums |" > summary
  print "|---|:-:|:-:|:-:|:-:|:-:|" > summary
  for (c = 1; c <= ncat; c++) {
    cat = order[c]
    if (!catcount[cat]) continue
    line = "| " label[cat] " | " catcount[cat] " |"
    for (t = 1; t <= ntools; t++) line = line " " (bycat[cat, t] + 0) " |"
    print line > summary
  }
  line = "| **Total** | **" n "** |"
  for (t = 1; t <= ntools; t++) line = line " **" (total[t] + 0) "** |"
  print line > summary
  print "" > summary
  print "Detects means the data about the attack appears in the output of the tool; for tripwatch the" > summary
  print "judgement stays with the verifier: its real-time rules run on what the watchers of the sensor saw while the" > summary
  print "scenario ran. The scenarios in the \"Limits\" category (a dropper or an SSH key that appear and disappear" > summary
  print "between two checks) are beyond any tool that only compares states; for them tripwatch relies on its" > summary
  print "real-time watchers, and the table says which ones they catch." > summary
  print "Method, results per scenario, versions and cost in [bench/RESULTS.md](bench/RESULTS.md)." > summary
}
' "$joined"
