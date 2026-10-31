package web

import (
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// literals is what a reading of a script finds: its string literals, decoded, and how many
// regular expression literals it holds.
type literals struct {
	strs    []string
	regexps int
}

func (l literals) equal(o literals) bool {
	return l.regexps == o.regexps && slices.Equal(l.strs, o.strs)
}

type oracleVisitor struct{ found *literals }

func (v oracleVisitor) Enter(n js.INode) js.IVisitor {
	add := func(raw []byte) {
		s, _, _ := jsFoldLiteral(raw, 0)
		v.found.strs = append(v.found.strs, string(s))
	}
	// A directive and a module's name are string literals the tokenizer reads as any other;
	// the parser keeps them apart.
	switch n := n.(type) {
	case *js.DirectivePrologueStmt:
		add(n.Value)
	case *js.PropertyName:
		// Keys are left out on both sides: the parser reads a quoted one as a name when it can
		// ("return": ...) and keeps no quotes to tell.
		if n.Computed != nil {
			js.Walk(v, n.Computed)
		}
		return nil
	case *js.ImportStmt:
		add(n.Module)
	case *js.ExportStmt:
		if n.Module != nil {
			add(n.Module)
		}
	}
	if lit, ok := n.(*js.LiteralExpr); ok {
		switch lit.TokenType {
		case js.StringToken:
			s, _, _ := jsFoldLiteral(lit.Data, 0)
			v.found.strs = append(v.found.strs, string(s))
		case js.RegExpToken:
			v.found.regexps++
		}
	}
	return v
}

func (oracleVisitor) Exit(js.INode) {}

// oracle reads src with a JavaScript parser, used only here as the reference; false when src is
// not a valid script.
func oracle(src []byte) (literals, bool) {
	ast, err := js.Parse(parse.NewInputBytes(slices.Clone(src)), js.Options{})
	if err != nil {
		return literals{}, false
	}
	var found literals
	js.Walk(oracleVisitor{&found}, ast)
	slices.Sort(found.strs)
	return found, true
}

// ours is what the tokenizer finds in src with one reading of an uncertain "/".
func ours(src []byte, regexAfterClose bool) literals {
	content, _ := jsNormalize(src, len(src))
	toks, _, _, _, _ := jsTokens(content, regexAfterClose, false, nil, len(content))
	var found literals
	for k, t := range toks {
		key := k > 0 && k+1 < len(toks) && toks[k+1].text == ":" && (toks[k-1].text == "{" || toks[k-1].text == ",")
		switch {
		case t.kind == 'r':
			found.regexps++
		case t.kind == 's' && !key && (content[t.at] == '\'' || content[t.at] == '"'):
			found.strs = append(found.strs, t.text)
		}
	}
	slices.Sort(found.strs)
	return found
}

// agrees reports whether one of the tokenizer's readings finds what the parser finds.
func agrees(src []byte) (want literals, valid, ok bool) {
	want, valid = oracle(src)
	if !valid {
		return want, false, true
	}
	return want, true, ours(src, true).equal(want) || ours(src, false).equal(want)
}

// jsGen writes valid scripts dense in the places where a "/" divides or starts a pattern and a
// quote opens a string or sits in one.
type jsGen struct {
	rng   *rand.Rand
	depth int
}

func (g *jsGen) pick(xs ...string) string { return xs[g.rng.IntN(len(xs))] }

func (g *jsGen) str() string {
	return g.pick(`'a'`, `"b"`, `'it\'s'`, `"/*"`, `'*/'`, `"//"`, `'/'`, `"a/b"`, `'"'`, `"'"`, `'\\'`, `"x\"y"`, `'payment[c'`)
}

func (g *jsGen) regexp() string {
	return g.pick(`/a/`, `/a/g`, `/['"]/`, `/[/]/`, `/\//`, `/x*/i`, `/["']+$/`, `/\d+/`, `/=/`, `/[*/]/`)
}

func (g *jsGen) expr() string {
	if g.depth > 3 {
		return g.pick("x", "1", g.str(), g.regexp())
	}
	g.depth++
	defer func() { g.depth-- }()
	switch g.rng.IntN(16) {
	case 0:
		return g.str()
	case 1:
		return g.regexp()
	case 2:
		return "(" + g.expr() + ")/" + g.pick("2", "x", "(y)")
	case 3:
		return g.expr() + "/" + g.expr()
	case 4:
		return g.regexp() + ".test(" + g.expr() + ")"
	case 5:
		return "{a:" + g.expr() + "}"
	case 6:
		return "x?" + g.expr() + ":" + g.pick("{}", g.expr())
	case 7:
		return "function(){return " + g.expr() + "}"
	case 8:
		return "(function(){})/2"
	case 9:
		return "[" + g.expr() + "," + g.expr() + "]"
	case 10:
		return "x[" + g.str() + "]/" + g.pick("2", "x")
	case 11:
		return "typeof " + g.regexp()
	case 12:
		return "i++/" + g.pick("2", "x")
	case 13:
		return "class{}"
	case 14:
		return g.expr() + "+" + g.expr()
	}
	return g.pick("x", "y", "1", "2")
}

func (g *jsGen) stmt() string {
	if g.depth > 3 {
		return "x=" + g.expr() + ";"
	}
	g.depth++
	defer func() { g.depth-- }()
	switch g.rng.IntN(12) {
	case 0:
		return "if(" + g.expr() + ")" + g.stmt()
	case 1:
		return "if(x){" + g.stmt() + "}" + g.regexp() + ".test(x);"
	case 2:
		return "{" + g.stmt() + "}" + g.regexp() + ";"
	case 3:
		return "l:{" + g.stmt() + "}"
	case 4:
		return "function f(){" + g.stmt() + "return " + g.expr() + "}"
	case 5:
		return "while(0)" + g.regexp() + ".test(x);"
	case 6:
		return "for(;0;){" + g.stmt() + "}"
	case 7:
		return "var v=" + g.expr() + ";"
	case 8:
		return "x=" + g.expr() + "\n"
	case 9:
		return "do{" + g.stmt() + "}while(0);"
	case 10:
		return "// " + g.str() + "\n"
	}
	return "/* " + g.regexp() + " */x=" + g.expr() + ";"
}

// The tokenizer finds the string and pattern literals a JavaScript parser finds, on generated
// scripts full of the places a tokenizer can mistake.
func TestTokenizerAgainstParser(t *testing.T) {
	g := &jsGen{rng: rand.New(rand.NewPCG(3, 4))} //nolint:gosec // a seeded generator, so a failure repeats
	valid, failed := 0, 0
	for range 20000 {
		var b strings.Builder
		for range 1 + g.rng.IntN(5) {
			b.WriteString(g.stmt())
		}
		src := []byte(b.String())
		want, ok, same := agrees(src)
		if !ok {
			continue
		}
		valid++
		if !same {
			if failed++; failed <= 5 {
				t.Errorf("%q: parser %v, tokenizer %v / %v", src, want, ours(src, true), ours(src, false))
			}
		}
	}
	t.Logf("%d valid scripts, %d read differently", valid, failed)
	if valid < 5000 {
		t.Errorf("only %d valid scripts generated", valid)
	}
}

// With WEB_CORPUS, the same comparison on every script of a corpus of real ones. Patterns must
// match in number: a different count is a "/" or a quote read the wrong way. Strings may differ
// in text where the normalization of white space, a literal longer than what is kept, or a key
// the parser reads as a name changes it, and are only logged.
func TestTokenizerAgainstParserOnCorpus(t *testing.T) {
	root := os.Getenv("WEB_CORPUS")
	if root == "" {
		t.Skip("WEB_CORPUS not set")
	}
	valid, failed := 0, 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error { //nolint:gosec // the corpus the test is given
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".js") {
			return nil
		}
		src, err := os.ReadFile(p) //nolint:gosec // the test's own corpus
		if err != nil || len(src) > skimmerChunk {
			return nil
		}
		want, ok, same := agrees(src)
		if !ok {
			return nil
		}
		valid++
		if !same {
			failed++
			o, d := ours(src, true), ours(src, false)
			if o.regexps != want.regexps && d.regexps != want.regexps {
				t.Errorf("%s: %d patterns, the tokenizer reads %d or %d", strings.TrimPrefix(p, root), want.regexps, o.regexps, d.regexps)
			}
		}
		return nil
	})
	t.Logf("%d valid scripts, %d with strings read differently", valid, failed)
}
