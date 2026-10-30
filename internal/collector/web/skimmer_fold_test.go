package web

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A hostile script cannot make the folding slow or deep: nested parentheses, endless chains,
// arrays never joined and unterminated literals are read in bounded time.
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
		start := time.Now()
		foldedStrings([]byte(src))
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: %v", name, d)
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
