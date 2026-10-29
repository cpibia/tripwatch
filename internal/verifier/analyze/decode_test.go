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

// A few KB of gzip expanding into millions of tiny objects is refused before it is decoded:
// the whole snapshot past maxSnapshotValues, one collector's result past maxResultValues.
func TestDecodeRefusesValueBombs(t *testing.T) {
	bomb := func(n int) string {
		return `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]},"processes":{"processes":[` + strings.Repeat(`{},`, n) + `{}]}}}}`
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := Decode(gz(t, bomb(5_000_000)))
	st, resultErr := Decode(gz(t, bomb(1_000_000)))
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "values") {
		t.Errorf("err = %v", err)
	}
	if resultErr != nil || st.Processes != nil || !strings.Contains(st.Errors["processes"], "result refused") || st.Accounts == nil {
		t.Errorf("an inflated result: %v, processes %v, errors %v, accounts %v", resultErr, st.Processes, st.Errors, st.Accounts)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 400<<20 {
		t.Errorf("refusing the bombs allocated %d MB", grown>>20)
	}
	if _, err := Decode(gz(t, strings.Repeat("[", 100)+strings.Repeat("]", 100))); err == nil {
		t.Error("deep nesting accepted")
	}
}

// Results that each fit but together pass maxDecodedValues: the largest is left out, named in
// the errors, and the others are decoded.
func TestDecodeBoundsResultsTogether(t *testing.T) {
	result := func(n int) string { return `{"processes":[` + strings.Repeat(`{"pid":1},`, n) + `{"pid":1}]}` }
	doc := `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]},"processes":` + result(100_000) +
		`,"sockets":{"listening":[` + strings.Repeat(`{},`, 200_000) + `{}]},"kernel":{"modules":[` + strings.Repeat(`{},`, 230_000) + `{}]}}}}`
	st, err := Decode(gz(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	if st.Accounts == nil || st.Processes == nil || st.Kernel != nil || !strings.Contains(st.Errors["kernel"], "together") {
		t.Errorf("accounts %v, processes %v, kernel %v, errors %v", st.Accounts != nil, st.Processes != nil, st.Kernel != nil, st.Errors)
	}
}

func TestDecodeSnapshot(t *testing.T) {
	st, err := Decode(gz(t, `{"snapshot":{"taken_at":"2026-10-22T10:00:00Z","results":{"accounts":{"accounts":[{"name":"root","uid":0}]},"unknown":{}},"warnings":["w"]}}`))
	if err != nil || st.Accounts == nil || len(st.Accounts.Accounts) != 1 || len(st.Warnings) != 1 {
		t.Errorf("state = %+v, %v", st, err)
	}
}
