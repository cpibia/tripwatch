package ui

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// The host page lists the events of the host as data: markup sent by the host stays text.
func TestHostPageListsEvents(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.store.Enroll(ctx, "web-01", make([]byte, 32), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	h.login()
	if _, body := h.get("/hosts/web-01"); !strings.Contains(body, "No events yet") {
		t.Fatal("empty timeline not explained")
	}
	if _, err := h.store.AddEvents(ctx, []store.Event{
		{HostID: "web-01", Seq: 4, At: now.Add(-time.Minute), Class: "upload", Op: "create", Path: "/srv/app/uploads/<b>x</b>.php",
			Data: []byte(`{"class":"upload","op":"create","path":"/srv/app/uploads/x.php","size":42,"sha256":"0123456789abcdef0123","mode":"-rw-r--r--"}`)},
		{HostID: "web-01", Seq: 5, At: now, Class: "exec", Op: "exec", Path: "/usr/bin/bash", PackageManager: true,
			Data: []byte(`{"class":"exec","op":"exec","reason":"web_user_tool","exe":"/usr/bin/bash","cmdline":"bash -c id","parent":"php-fpm8.2","user":33}`)},
	}, now); err != nil {
		t.Fatal(err)
	}
	_, body := h.get("/hosts/web-01")
	for _, want := range []string{"Real-time events", "&lt;b&gt;x&lt;/b&gt;.php", "SHA-256 0123456789ab", "started by the web server&#39;s user", "bash -c id · parent php-fpm8.2 · uid 33", "during a package installation"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
	if strings.Index(body, "/usr/bin/bash") > strings.Index(body, "x&lt;/b&gt;.php") {
		t.Error("events not newest first")
	}
}

// Events stored raw keep a right-to-left override or a line break out of the page.
func TestEventRowsEscapeHostText(t *testing.T) {
	rows := eventRows([]store.Event{{Class: "exec", Op: "exec", Path: "/srv/x\u202egnp.php",
		Data: []byte(`{"class":"exec","reason":"webshell","cmdline":"sh -c id\nAll clear"}`)}})
	if rows[0].Subject != `/srv/x\u202egnp.php` || !strings.Contains(rows[0].Detail, `id\x0aAll clear`) {
		t.Errorf("subject %q, detail %q", rows[0].Subject, rows[0].Detail)
	}
}
