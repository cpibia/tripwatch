package web

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// Heredocs and nowdocs are strings to PHP: a "?>" inside one does not end the block.
func TestCodeInDataHeredoc(t *testing.T) {
	for in, want := range map[string]string{
		"<?php $x = <<<EOT\n?>\nEOT;\nsystem($_GET['c']);":                      "exec_request_input",
		"<?php $x = <<<'EOT'\n?>\nEOT;\nsystem($_GET['c']);":                    "exec_request_input",
		"<?php $x = <<<\"EOT\"\n?>\nEOT;\nsystem($_GET['c']);":                  "exec_request_input",
		"<?php $x = <<<EOT\n  ?>\n  EOT;\nsystem($_GET['c']);":                  "exec_request_input",
		"<?php $x = <<<EOT\n?> EOTX\nEOT, 1;\nsystem($_GET['c']);":              "exec_request_input",
		"<?php $x = <<<EOT\nnever closed ?>\nsystem($_GET['c']);":               "exec_request_input",
		"<?php $x = <<<EOT\ntext\nEOT;\n?> after the block: system($_GET['c'])": "",
	} {
		got := strings.Join(first(codeInData([]byte(in), nil)), ",")
		if !strings.Contains(got, want) || (want == "" && got != "") {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// The lexer's state goes from one piece to the next: content given a byte at a time, or split
// anywhere, is judged as in one piece.
func TestCodeSearchPieces(t *testing.T) {
	inputs := []string{
		"log line\n<?php /* ?> */ $s = '?>'; $h = <<<EOT\n?>\n  EOT;\n# ?\nsystem($_GET['c']); ?> text <?= `id` ?>",
		"<?php" + strings.Repeat(" ", 3000) + "eval($_POST[x]);",
		"<?xml version=\"1.0\"?><a>system($_GET)</a> <?php+system($_GET[c]);",
	}
	for n, in := range inputs {
		whole := first(codeInData([]byte(in), nil))
		if (n < 2) != (len(whole) > 0) {
			t.Fatalf("whole %.40q: %v", in, whole)
		}
		for _, size := range []int{1, 2, 3, 7, 64} {
			c := &codeSearch{}
			for i := 0; i < len(in); i += size {
				c.feed([]byte(in[i:min(i+size, len(in))]), i+size >= len(in))
			}
			if !slices.Equal(c.sigs, whole) {
				t.Errorf("pieces of %d: %v, whole %v, in %.40q", size, c.sigs, whole, in)
			}
		}
	}
}

// Binary data holds open tags and backticks by chance; the blocks it makes cannot compile, so
// their weak signals are dropped. Code planted in the same file still counts.
func TestCodeInDataBinary(t *testing.T) {
	// Without the rule, three in four random files of 5 MB raise backtick_exec.
	noise := make([]byte, 5<<20)
	for seed := range uint64(3) {
		r := rand.NewChaCha8([32]byte{byte(seed)})
		_, _ = r.Read(noise)
		if got := first(codeInData(noise, nil)); len(got) > 0 {
			t.Errorf("random file %d: %v", seed, got)
		}
	}
	binary := string(noise[:64<<10])
	for in, want := range map[string]string{
		"%PDF-1.7\n" + binary + "<?= `$_GET[c]` ?>" + binary:     "backtick_exec",
		binary + "<?php $f = getallheaders(); ?>" + binary:       "dangerous_call",
		binary + "<?php echo `id`; __halt_compiler();" + binary:  "backtick_exec",
		binary + "<?php echo `id`; __HALT_COMPILER ();" + binary: "backtick_exec",
		binary + "<?php system($_GET['c']); \x01" + binary:       "exec_request_input",
		"<?php echo `id`; \x01 ?>":                               "",
		"<?php $f = getallheaders(); \x7f ?>":                    "",
		"<?php echo `id`; $a__halt_compiler = 1; \x01 ?>":        "",
		"<?php echo `id`; $o->__halt_compiler(); \x01 ?>":        "",
		"<?php echo `id`; $o-> __halt_compiler(); \x01 ?>":       "",
		"<?php echo `id`; A\\__halt_compiler(); \x01 ?>":         "",
		"<?php echo `id`; $x = '\x01'; /* \x02 */ // \x03\n ?>":  "backtick_exec",
	} {
		got := strings.Join(first(codeInData([]byte(in), nil)), ",")
		if !strings.Contains(got, want) || (want == "" && got != "") {
			t.Errorf("%.60q: %q, want %q", in, got, want)
		}
	}
}
