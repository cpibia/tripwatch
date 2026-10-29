package analyze

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CleanHostText rewrites, in place, every string reached from v (a pointer) so that line breaks,
// control characters and invisible formatting characters read as escapes. All of it was written
// on the monitored host, where a file name can hold a line break followed by a line that looks
// like the verifier's own, or a right-to-left override that shows x.php as xphp.png. Alert
// details keep their line breaks, so the only ones left are those the verifier writes. Tabs stay:
// crontab and configuration lines are full of them.
func CleanHostText(v any) {
	cleanValue(reflect.ValueOf(v), 0)
}

// maxCleanDepth stops at a depth decoded JSON never reaches: snapshots are refused past 32.
const maxCleanDepth = 64

func cleanValue(v reflect.Value, depth int) {
	if depth > maxCleanDepth {
		return
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			cleanValue(v.Elem(), depth+1)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if f := v.Field(i); f.CanSet() {
				cleanValue(f, depth+1)
			}
		}
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := range v.Len() {
			cleanValue(v.Index(i), depth+1)
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		iter := v.MapRange()
		type entry struct{ k, v reflect.Value }
		var changed []entry
		var stale []reflect.Value
		for iter.Next() {
			k, val := iter.Key(), iter.Value()
			nk := reflect.New(k.Type()).Elem()
			nk.Set(k)
			cleanValue(nk, depth+1)
			nv := reflect.New(val.Type()).Elem()
			nv.Set(val)
			cleanValue(nv, depth+1)
			if !nk.Equal(k) {
				stale = append(stale, k)
			}
			changed = append(changed, entry{nk, nv})
		}
		for _, k := range stale {
			v.SetMapIndex(k, reflect.Value{})
		}
		for _, e := range changed {
			v.SetMapIndex(e.k, e.v)
		}
	case reflect.String:
		if v.CanSet() {
			if s := v.String(); hostTextHidden(s) {
				v.SetString(escapeHostText(s))
			}
		}
	}
}

func hiddenRune(r rune) bool {
	return (unicode.IsControl(r) && r != '\t') || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

func hostTextHidden(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, hiddenRune)
}

func escapeHostText(s string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "�") {
		switch {
		case !hiddenRune(r):
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}
