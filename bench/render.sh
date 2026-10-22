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
function cell(v) { return v == "yes" ? "✅" : (v == "blocked" ? "⛔ bloccato" : "❌") }
function mb(kb) { return kb == "-" ? "-" : sprintf("%.0f MB", kb / 1024) }
function secs(s) { return s == "-" ? "oltre 900 s" : sprintf("%.1f s", s) }
# chart draws one horizontal bar per tool on a track as long as the scenario count. The colors
# follow the light and dark surfaces of the page that shows it.
function chart(file, n, commit, os,    t, y, w, track, left) {
  left = 132; track = 460
  print "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"720\" height=\"300\" viewBox=\"0 0 720 300\" role=\"img\" aria-labelledby=\"title desc\">" > file
  print "<title id=\"title\">Scenari d'\''attacco rilevati su " n "</title>" > file
  printf "<desc id=\"desc\">tripwatch %d, AIDE %d, rkhunter %d, debsums %d su %d scenari.</desc>\n", total[1], total[2], total[3], total[4], n > file
  print "<style>" > file
  print "svg { --surface: #fcfcfb; --track: #ebeae6; --bar: #2a78d6; --text: #0b0b0b; --muted: #52514e; font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Helvetica, Arial, sans-serif; }" > file
  print "@media (prefers-color-scheme: dark) { svg { --surface: #1a1a19; --track: #2e2e2c; --bar: #3987e5; --text: #f0efec; --muted: #c3c2b7; } }" > file
  print ".surface { fill: var(--surface); } .track { fill: var(--track); } .bar { fill: var(--bar); }" > file
  print ".title { fill: var(--text); font-size: 17px; font-weight: 600; } .sub, .foot { fill: var(--muted); font-size: 13px; }" > file
  print ".name { fill: var(--text); font-size: 15px; } .value { fill: var(--text); font-size: 15px; font-weight: 600; font-variant-numeric: tabular-nums; } .foot { font-size: 12px; }" > file
  print "</style>" > file
  print "<rect class=\"surface\" width=\"720\" height=\"300\" rx=\"12\"/>" > file
  print "<text class=\"title\" x=\"28\" y=\"42\">Scenari d'\''attacco rilevati su " n "</text>" > file
  print "<text class=\"sub\" x=\"28\" y=\"64\">Stesso host Debian per tutti, configurazione di default di ogni strumento</text>" > file
  for (t = 1; t <= ntools; t++) {
    y = 96 + (t - 1) * 44
    w = int(track * total[t] / n + 0.5)
    printf "<text class=\"name\" x=\"28\" y=\"%d\">%s</text>\n", y + 14, tool[t] > file
    printf "<rect class=\"track\" x=\"%d\" y=\"%d\" width=\"%d\" height=\"18\" rx=\"4\"/>\n", left, y, track > file
    if (w > 0) {
      printf "<rect class=\"bar\" x=\"%d\" y=\"%d\" width=\"%d\" height=\"18\" rx=\"4\"/>\n", left, y, w > file
      printf "<rect class=\"bar\" x=\"%d\" y=\"%d\" width=\"%d\" height=\"18\"/>\n", left, y, (w < 4 ? w : 4) > file
    }
    printf "<text class=\"value\" x=\"%d\" y=\"%d\">%d su %d</text>\n", left + track + 14, y + 14, total[t], n > file
  }
  printf "<text class=\"foot\" x=\"28\" y=\"280\">Commit %s, %s. Metodo e dettaglio per scenario in bench/RESULTS.md</text>\n", commit, os > file
  print "</svg>" > file
  close(file)
}
BEGIN {
  ntools = split("tripwatch AIDE rkhunter debsums", tool, " ")
  ncat = split("persistence privilege integrity runtime web limits", order, " ")
  label["persistence"] = "Persistenza"
  label["privilege"] = "Privilegi"
  label["integrity"] = "Integrità del sistema"
  label["runtime"] = "Processi e rete"
  label["web"] = "Applicazioni web"
  label["limits"] = "Limiti: attacchi tra due controlli e trappole"
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

  print "# Benchmark di rilevamento"
  print ""
  printf "Commit `%s`, %s, container %s su %s. Strumenti di confronto: AIDE %s, rkhunter %s, debsums %s,\n", commit, day, version["os"], arch, version["aide"], version["rkhunter"], version["debsums"]
  print "con la configurazione di default dei pacchetti Debian. Si rigenera con `bench/run.sh`."
  print ""
  print "## Metodo"
  print ""
  print "Ogni scenario parte da un container pulito, uguale per tutti: una Debian con un sito WordPress, su cui"
  print "ogni strumento ha già preso la sua baseline. Lo scenario applica l'\''attacco, poi tutti gli strumenti"
  print "girano una volta. Uno strumento **rileva** lo scenario quando nel suo output le righe che citano"
  print "l'\''artefatto dell'\''attacco (un percorso, il commento di una chiave, una porta) sono diverse da quelle"
  print "della baseline: qualcosa di nuovo è comparso o qualcosa di noto è cambiato. Per tripwatch si confrontano"
  print "gli oggetti JSON dello snapshot che contengono l'\''artefatto: il giudizio finale spetta al verificatore,"
  print "qui si misura se il dato arriva. **Bloccato** vuol dire che lo strumento non ha finito entro 900 s."
  print ""
  if (fp == "") print "Lo scenario di controllo, senza attacco, non produce differenze per nessuno strumento."
  else print "Attenzione: lo scenario di controllo, senza attacco, produce differenze per:" fp "."
  print ""
  print "## Risultati per scenario"
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
  print "## Costo di un controllo completo"
  print ""
  print "Misurato sullo scenario di controllo, nello stesso container."
  print ""
  print "| Strumento | Tempo | Memoria massima |"
  print "|---|--:|--:|"
  for (t = 1; t <= ntools; t++) printf "| %s | %s | %s |\n", tool[t], secs(cost_s[t]), mb(cost_m[t])

  print "Su " n " scenari d'\''attacco riprodotti in un container Debian (commit `" commit "`), quanti ne rileva" > summary
  print "ciascuno strumento con la configurazione di default:" > summary
  print "" > summary
  print "![Scenari rilevati su " n ": tripwatch " total[1] ", AIDE " total[2] ", rkhunter " total[3] ", debsums " total[4] "](bench/detection.svg)" > summary
  print "" > summary

  chart(svg, n, commit, version["os"])
  print "| Categoria | Scenari | tripwatch | AIDE | rkhunter | debsums |" > summary
  print "|---|:-:|:-:|:-:|:-:|:-:|" > summary
  for (c = 1; c <= ncat; c++) {
    cat = order[c]
    if (!catcount[cat]) continue
    line = "| " label[cat] " | " catcount[cat] " |"
    for (t = 1; t <= ntools; t++) line = line " " (bycat[cat, t] + 0) " |"
    print line > summary
  }
  line = "| **Totale** | **" n "** |"
  for (t = 1; t <= ntools; t++) line = line " **" (total[t] + 0) "** |"
  print line > summary
  print "" > summary
  print "Rileva vuol dire che il dato sull'\''attacco compare nell'\''output dello strumento; per tripwatch il" > summary
  print "giudizio resta al verificatore. Gli scenari della categoria \"Limiti\" (un dropper o una chiave SSH" > summary
  print "che compaiono e spariscono tra due controlli) misurano il limite di chi confronta stati, tripwatch" > summary
  print "compreso. Metodo, risultati per scenario, versioni e costo in [bench/RESULTS.md](bench/RESULTS.md)." > summary
}
' "$joined"
