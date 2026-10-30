package web

import (
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
	} {
		start := time.Now()
		foldedStrings([]byte(src))
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: %v", name, d)
		}
	}
}
