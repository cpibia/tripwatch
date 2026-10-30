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
		// A carriage return alone ends a line for PHP: it closes a line comment and follows the
		// heredoc's opening, so what comes after runs.
		"log <?php //x\rsystem($_GET['c']);\n":                 "exec_request_input",
		"log <?php #x\rsystem($_GET['c']);\n":                  "exec_request_input",
		"log <?php $x=<<<EOT\r?>\rEOT;\rsystem($_GET['c']);":   "exec_request_input",
		"log <?php $x=<<<'EOT'\r?>\rEOT;\rsystem($_GET['c']);": "exec_request_input",
		"log <?$x=<<<EOT\r\x01\rEOT;\rsystem($_GET['c']);":     "exec_request_input",
	} {
		got := strings.Join(first(searchData([]byte(in), nil)), ",")
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
		whole := first(searchData([]byte(in), nil))
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

// The short pass reads ahead of "<?" to judge a word glued to it: the verdict does not depend on
// where the content is split.
func TestShortTagPieces(t *testing.T) {
	for _, in := range []string{
		"log <?phpinfo:system($_GET['c']);",
		"log <?php" + strings.Repeat("x", openTagLook) + ":system($_GET['c']);",
		"q=<?php+system($_GET[c]); <?xml version=\"1.0\"?>",
	} {
		whole := first(searchData([]byte(in), nil))
		for _, size := range []int{1, 2, 3, 7, 64} {
			d := newDataSearch(nil, mediaOrDocument([]byte(in)))
			for i := 0; i < len(in); i += size {
				d.feed([]byte(in[i:min(i+size, len(in))]), i+size >= len(in))
			}
			if got := d.signatures(); !slices.Equal(got, whole) {
				t.Errorf("pieces of %d: %v, whole %v, in %.40q", size, got, whole, in)
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
		if got := first(searchData(noise, nil)); len(got) > 0 {
			t.Errorf("random file %d: %v", seed, got)
		}
	}
	binary := string(noise[:64<<10])
	for in, want := range map[string]string{
		"%PDF-1.7\n" + binary + "<?= `$_GET[c]` ?>" + binary:     "backtick_exec",
		binary + "<?php $f = getallheaders(); ?>" + binary:       "dangerous_call",
		binary + "<?php echo `$c`; __halt_compiler();" + binary:  "backtick_exec",
		binary + "<?php echo `$c`; __HALT_COMPILER ();" + binary: "backtick_exec",
		binary + "<?php system($_GET['c']); \x01" + binary:       "exec_request_input",
		"<?php echo `$c`; \x01 ?>":                               "",
		"<?php $f = getallheaders(); \x7f ?>":                    "",
		"<?php echo `$c`; $a__halt_compiler = 1; \x01 ?>":        "",
		"<?php echo `$c`; $o->__halt_compiler(); \x01 ?>":        "",
		"<?php echo `$c`; $o-> __halt_compiler(); \x01 ?>":       "",
		"<?php echo `$c`; A\\__halt_compiler(); \x01 ?>":         "",
		"<?php echo `$c`; $x = '\x01'; /* \x02 */ // \x03\n ?>":  "backtick_exec",
	} {
		got := strings.Join(first(searchData([]byte(in), nil)), ",")
		if !strings.Contains(got, want) || (want == "" && got != "") {
			t.Errorf("%.60q: %q, want %q", in, got, want)
		}
	}
}

// Interpolated code inside a string is code, with strings of its own: a quote or "?>" in it
// neither closes the string around it nor ends the block. Short open tags open a block whatever
// follows "<?". The verdict does not depend on how the content is split.
func TestCodeInDataInterpolation(t *testing.T) {
	deep := "<?php $x = \"" + strings.Repeat("{$a[\"", maxNested+1) + "\"; system($_GET['c']);"
	for in, want := range map[string]string{
		`log line <?php $x = "{$a["\""]}?>"; system($_GET['c']);`:                   "exec_request_input",
		`log line <?php $x = "${a["\""]}?>"; system($_GET['c']);`:                   "exec_request_input",
		"<?php $x = `{$a[\"`\"]}?>`; system($_GET['c']);":                           "exec_request_input",
		"<?php $x = \"{$a[\"{$b[\"\\\"\"]}\"]}?>\"; system($_GET['c']);":            "exec_request_input",
		"<?php $x = <<<EOT\n{$a[\"\nEOT\n?>\"]}\nEOT;\nsystem($_GET['c']);":         "exec_request_input",
		"<?php $x = <<<'EOT'\n{$a}?>\nEOT;\n?> after: system($_GET['c'])":           "",
		`<?php $x = "{ $a } $ "; ?> after: system($_GET['c'])`:                      "",
		`<?php $x = "\{$a}"; ?> after: system($_GET['c'])`:                          "",
		"log line <?system($_GET['c']);?> rest":                                     "exec_request_input",
		"log line <?\tsystem($_GET['c']);?> rest":                                   "exec_request_input",
		"<?xml version=\"1.0\"?><a>system($_GET['c'])</a>":                          "",
		"q=<?php+system($_GET[c]);":                                                 "",
		"log <?php:system($_GET['c']);":                                             "exec_request_input",
		"log <?PHP:system($_GET['c']);":                                             "exec_request_input",
		"log <?xml:system($_GET['c']);":                                             "exec_request_input",
		"log <?php::class;system($_GET['c']);":                                      "exec_request_input",
		"log <?phpinfo:system($_GET['c']);":                                         "exec_request_input",
		"log <?php_x::class;system($_GET['c']);":                                    "exec_request_input",
		"log <?xmlfoo :system($_GET['c']);":                                         "exec_request_input",
		"log <?phpinfo();system($_GET['c']);":                                       "exec_request_input",
		"log <?php" + strings.Repeat("x", openTagLook) + ":system($_GET['c']);":     "exec_request_input",
		"log <?phpinfo/**/:system($_GET['c']);":                                     "exec_request_input",
		"log <?phpinfo" + strings.Repeat(" ", openTagLook) + ":system($_GET['c']);": "exec_request_input",
		"<?php echo `id`;":                                                        "backtick_exec",
		"<?php putenv('PATH=/tmp/x'); echo `id`;":                                 "backtick_exec",
		"log <? `wp_posts` unclosed":                                              "",
		"log <?PHP_EOL; $f = $_GET['f']; $f($_GET['a']);":                         "dangerous_call",
		"log <?E_ALL; $f = $_POST['f']; $f();":                                    "dangerous_call",
		"log <?mso-application progid=x> then call_user_func_array(Array, Array)": "",
		"<?php echo `$c`;":                                                        "backtick_exec",
		"<?php echo `ls -la`;":                                                    "backtick_exec",
		"-- MySQL dump\nINSERT INTO `wp_options` VALUES (1,'note <? unclosed');\nINSERT INTO `wp_posts` (`ID`,`post_title`) VALUES (2,'x');\n": "",
		"log <?PHP_EOL;system($_GET['c']);":              "exec_request_input",
		"log <?XML_ERROR_NONE;system($_GET['c']);":       "exec_request_input",
		"log <?php\\x::class;system($_GET['c']);":        "exec_request_input",
		"log <?php+system($_GET['c']);":                  "",
		"log <?php;system($_GET['c']);":                  "",
		"log <? /* x\n<?php system($_GET['c']); ?> */ y": "exec_request_input",
		"Unsupported instruction <?mso-application> in import\n#0 call_user_func_array(Array, Array)\n#1 require_once('/app/x.php')": "",
		"<?mso-application progid=\"Excel.Sheet\"?><x/>":                                                                                         "",
		"<?xml-stylesheet type=\"text/xsl\" href=\"s.xsl\"?><r>system($_GET['c'])</r>":                                                           "",
		"<?mso-application ?><r>system($_GET['c'])</r>":                                                                                          "",
		"log <?$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                              "dangerous_call",
		"log <?@$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                             "dangerous_call",
		"log <?/**/$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                          "dangerous_call",
		"log <?(function(){$c=$_GET[\"c\"]??\"id\";system($c);})();":                                                                             "dangerous_call",
		"log <?echo\"x\";$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                    "dangerous_call",
		"log <?PHP_EOL.$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                      "dangerous_call",
		"log <?PHP_EOL[0];$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                   "dangerous_call",
		"log <?PHP_EOL-1;$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                    "dangerous_call",
		"log <?E_ALL|$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                        "dangerous_call",
		"log <?PHP_EOL .$c=$_GET[\"c\"]??\"id\";system($c);":                                                                                     "dangerous_call",
		"log <?$c=$_GET[\"c\"]??\"id\";echo `$c`;":                                                                                               "backtick_exec",
		"log <?PHP_EOL>1;$c=$_GET[\"c\"];system($c);":                                                                                            "dangerous_call",
		"log <?echo PHP_EOL==1;$c=$_GET[\"c\"];system($c);":                                                                                      "dangerous_call",
		"log <?const X=1;$c=$_GET[\"c\"];system($c);":                                                                                            "dangerous_call",
		"log <?print true===1;$c=$_GET[\"c\"];system($c);":                                                                                       "dangerous_call",
		"log <?foo>1;$c=$_GET[\"c\"];system($c);":                                                                                                "",
		"<?php define(\"foo\",1);?>\nlog <?foo>1;$c=$_GET[\"c\"];system($c);":                                                                    "dangerous_call",
		"<?php define(\"xml\",1);?>\nlog <?xml>1;$c=$_GET[\"c\"];system($c);":                                                                    "dangerous_call",
		"<?php const xml=1;?>\nlog <?xml>1;$c=$_GET[\"c\"];system($c);":                                                                          "dangerous_call",
		"<?php define(\"php\",1);?>\nlog <?php>1;$c=$_GET[\"c\"];system($c);":                                                                    "dangerous_call",
		"<?php define(\"xml\",1);?>\nlog <?xml >1;$c=$_GET[\"c\"];system($c);":                                                                   "dangerous_call",
		"<?php define(\"xml\",1);?>\nlog <?xml ;$c=$_GET[\"c\"];system($c);":                                                                     "dangerous_call",
		"<?php define(\"xml\",1);?>\nlog <?xml\t.$c=$_GET[\"c\"];system($c);":                                                                    "dangerous_call",
		"<?php define(\"XML\",1);?>\nlog <?XML >1;$c=$_GET[\"c\"];system($c);":                                                                   "dangerous_call",
		"<?php echo 1;?>\n<?xml version=\"1.0\"?><a>system($_GET['c'])</a>":                                                                      "",
		"log <?xml >1;$c=$_GET[\"c\"];system($c);":                                                                                               "",
		"log <? $f=\"put\".\"env\";$f(\"PATH=/w/bin\");echo `x`; ?>":                                                                             "backtick_exec",
		"log <? $f=strrev(\"vnetup\");$f(\"PATH=/w/bin\");echo `x`; ?>":                                                                          "backtick_exec",
		"log <? $_ENV;$f=strrev(\"vnetup\");$f(\"PATH=/w/bin\");echo `x`; ?>":                                                                    "backtick_exec",
		"log <? (\"put\".\"env\")(\"PATH=/w/bin\");echo `x`; ?>":                                                                                 "backtick_exec",
		"log <? \"putenv\"(\"PATH=/w/bin\");echo `x`; ?>":                                                                                        "backtick_exec",
		"log <? $a=[\"putenv\"];$a[0](\"PATH=/w/bin\");echo `x`; ?>":                                                                             "backtick_exec",
		"log <? $f=\"putenv\";${\"f\"}(\"PATH=/w/bin\");echo `x`; ?>":                                                                            "backtick_exec",
		"log <? array_map(\"put\".\"env\",[\"PATH=/w/bin\"]);echo `x`; ?>":                                                                       "backtick_exec",
		"log <? (new ReflectionFunction(\"put\".\"env\"))->invoke(\"PATH=/w/bin\");echo `x`; ?>":                                                 "backtick_exec",
		"log <? $r=new ReflectionFunction(\"put\".\"env\");$r->invokeArgs([\"PATH=/w/bin\"]);echo `x`; ?>":                                       "backtick_exec",
		"log <? Closure::fromCallable(\"put\".\"env\")->__invoke(\"PATH=/w/bin\");echo `x`; ?>":                                                  "backtick_exec",
		"INSERT INTO `wp_options` VALUES ('<? `x` $a ?>');":                                                                                      "",
		"log <?php>1;$c=$_GET[\"c\"];system($c);":                                                                                                "",
		"log <?x a=\"b\";$c=$_GET[\"c\"];system($c);":                                                                                            "",
		"<?php $x=<<<" + strings.Repeat("A", maxHeredocIDSize+2) + "\n/*\n" + strings.Repeat("A", maxHeredocIDSize+2) + ";\nsystem($_GET['c']);": "long_heredoc_label",
		"<?php $x=<<<" + strings.Repeat(" ", maxHeredocBlanks+1) + "A\n?>\nA;\nsystem($_GET['c']);":                                              "long_heredoc_label",
		"<?php $x=<<<" + strings.Repeat("A", maxHeredocIDSize-1) + "\n/*\n" + strings.Repeat("A", maxHeredocIDSize-1) + ";\nsystem($_GET['c']);": "dangerous_call",
		"log <?$c=$_GET[1];echo `{$c}`;":                                                                                                         "backtick_exec",
		"* > | <?>\n * > | a <?b?> c\nconst s = `${x} b`;":                                                                                       "",
		"def:/^ *\\[([^\\]]+)\\]: *<?([^\\s>]+)>?/,x=`a ${b} c`;exec(`${cmd}`)":                                                                  "",
		"f=<?(a) => { return `${a} b`; }; system(a)":                                                                                             "",
		"log <?$f=1; x = `${b}`;":                                                                                                                "",
		"log <?putenv('PATH=/tmp/x');echo `id`;":                                                                                                 "dangerous_call",
		deep:                                                                                                                                     "nested_interpolation",
	} {
		whole := strings.Join(first(searchData([]byte(in), nil)), ",")
		if !strings.Contains(whole, want) || (want == "" && whole != "") {
			t.Errorf("%.60q: %q, want %q", in, whole, want)
		}
		for _, size := range []int{1, 2, 3, 7} {
			d := newDataSearch(nil, mediaOrDocument([]byte(in)))
			for i := 0; i < len(in); i += size {
				d.feed([]byte(in[i:min(i+size, len(in))]), i+size >= len(in))
			}
			if got := strings.Join(d.signatures(), ","); got != whole {
				t.Errorf("pieces of %d of %.60q: %q, whole %q", size, in, got, whole)
			}
		}
	}
}

// A document's short blocks, which its compressed streams open by chance, spend no budget; code
// planted in it with a full open tag is still found.
func TestDocumentsSkipShortBlocks(t *testing.T) {
	noise := "%PDF-1.7\n" + strings.Repeat("<? "+strings.Repeat("a", 200)+" ?>", 50)
	left := int64(1000)
	if _, exhausted := searchData([]byte(noise), &left); exhausted || left != 1000 {
		t.Errorf("short blocks of a document spent the budget: %d left, exhausted %v", left, exhausted)
	}
	text := strings.TrimPrefix(noise, "%PDF-1.7\n")
	left = 1000
	if _, exhausted := searchData([]byte(text), &left); !exhausted {
		t.Error("the same short blocks outside a document spent nothing")
	}
	left = 1 << 20
	planted := "%PDF-1.7\n" + noise + "<?php system($_GET['c']); ?>"
	if sigs, _ := searchData([]byte(planted), &left); len(strongInDocuments(documentLike("data", []byte(planted)), sigs)) == 0 {
		t.Errorf("code planted in a document with a full tag: %v", sigs)
	}
}

// A block a document's streams open by chance, never closed, stops at documentBlockCode instead
// of spending the budget to the end of the file; a short planted block is still read whole.
func TestDocumentBlocksAreCut(t *testing.T) {
	noise := make([]byte, 2<<20)
	for i := range noise {
		noise[i] = byte('a' + i%23)
	}
	pdf := append([]byte("%PDF-1.7\n<?= "), noise...)
	left := int64(16 << 20)
	if _, exhausted := searchData(pdf, &left); exhausted || 16<<20-left > documentBlockCode+4096 {
		t.Errorf("an unclosed block of a document spent %d bytes", 16<<20-left)
	}
	left = 16 << 20
	planted := append(append([]byte("%PDF-1.7\n"), noise[:1<<20]...), "<?= system($_GET['c']); ?>"...)
	if sigs, _ := searchData(planted, &left); len(strongInDocuments(documentLike("data", planted), sigs)) == 0 {
		t.Errorf("a short block planted in a document: %v", sigs)
	}
}

// A database dump whose tool wrote its own header is told by its statements on backticked
// tables; text that opens a PHP block before them is not.
func TestDumpToldByItsStatements(t *testing.T) {
	dump := []byte("# Dump of database shop\n# ------------------------\n\nDROP TABLE IF EXISTS `wp_posts`;\nINSERT INTO `wp_posts` VALUES (1,'<?php echo `ls -la`; ?>');\n")
	if !documentLike("backup/mysql_2022-03-21", dump) {
		t.Error("a dump with a tool's header is not told")
	}
	if sigs, _ := searchData(dump, nil); len(strongInDocuments(documentLike("data", dump), sigs)) != 0 {
		t.Errorf("a dump's quoted code reported: %v", sigs)
	}
	if documentLike("backup/mysql_2022-03-21", []byte("<?php `id`; ?>\nINSERT INTO `x` VALUES (1);\n")) {
		t.Error("a PHP file with a statement taken for a dump")
	}
	// One statement line heads any file its writer chooses: only a name a dump can have counts.
	for name, want := range map[string]bool{"backup/db.sql": true, "backup/db.20220321": true, "uploads/x.txt": false, "uploads/favicon.ico": false, "var/x.php": false} {
		if got := documentLike(name, dump); got != want {
			t.Errorf("%s told a dump: %v, want %v", name, got, want)
		}
	}
}

// searchData is codeInData on content told a document or not as a data file named "data" is.
func searchData(content []byte, codeLeft *int64) ([]string, bool) {
	return codeInData(content, codeLeft, documentLike("data", content))
}
