package notify

import (
	"strings"
	"testing"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

func TestCompose(t *testing.T) {
	subject, body := Compose([]store.Alert{
		{ID: 7, HostID: "web-01", Severity: "critical", Title: "Secondo account root: svcadmin", Detail: "UID 0\nHome /var/lib/x"},
		{ID: 8, HostID: "web-02", Severity: "high", Title: "Nuova chiave SSH"},
	}, "https://tripwatch.example.com/")
	if subject != "[tripwatch] 1 critici, 2 allarmi su 2 server" {
		t.Errorf("subject = %q", subject)
	}
	for _, want := range []string{"CRITICAL · web-01 · Secondo account root", "  UID 0\n  Home /var/lib/x", "https://tripwatch.example.com/alerts/7"} {
		if !strings.Contains(body, want) {
			t.Errorf("body misses %q:\n%s", want, body)
		}
	}
	if strings.ContainsAny(subject, "\r\n") {
		t.Error("header injection through the subject")
	}
}
