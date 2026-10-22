package analyze

import (
	"bytes"
	"compress/gzip"
	"runtime"
	"strings"
	"testing"
)

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

// A few KB of gzip expanding into millions of tiny objects is refused before it is decoded.
func TestDecodeRefusesValueBombs(t *testing.T) {
	bomb := `{"snapshot":{"results":{"processes":{"processes":[` + strings.Repeat(`{},`, 3_000_000) + `{}]}}}}`
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := Decode(gz(t, bomb))
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "too many values") {
		t.Errorf("err = %v", err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 200<<20 {
		t.Errorf("refusing the bomb allocated %d MB", grown>>20)
	}
	if _, err := Decode(gz(t, strings.Repeat("[", 100)+strings.Repeat("]", 100))); err == nil {
		t.Error("deep nesting accepted")
	}
}

func TestDecodeSnapshot(t *testing.T) {
	st, err := Decode(gz(t, `{"snapshot":{"taken_at":"2026-10-22T10:00:00Z","results":{"accounts":{"accounts":[{"name":"root","uid":0}]},"unknown":{}},"warnings":["w"]}}`))
	if err != nil || st.Accounts == nil || len(st.Accounts.Accounts) != 1 || len(st.Warnings) != 1 {
		t.Errorf("state = %+v, %v", st, err)
	}
}
