//go:build linux

package watch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
)

// No reader of the sensor opens a decoy: not a whole round of the system collectors, which hash,
// read attributes and walk for privileged files, and not the watcher reporting changes to it. A
// second inotify instance on each decoy sees every open of it.
func TestDecoysNeverOpenedInARoundOrByEvents(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"etc/sudoers.d", "srv/app/uploads", "usr/bin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	decoys := []string{"etc/sudoers.d/90-backup", "srv/app/uploads/db-backup.sql", "usr/bin/helper"}
	for _, d := range decoys {
		if err := os.WriteFile(filepath.Join(root, d), []byte("bait\n"), 0o4755); err != nil { //nolint:gosec // setuid, so the privileged walk reaches it
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(root, decoys[1]), filepath.Join(root, "srv/app/uploads/copy.sql")); err != nil {
		t.Fatal(err)
	}
	src := collector.NewSource(root)
	d := system.Decoys{Paths: decoys}
	d.Refresh(src)
	t.Cleanup(func() { collector.SetDecoys(src, nil) })

	in, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(in) }()
	for _, p := range decoys {
		if _, err := unix.InotifyAddWatch(in, filepath.Join(root, p), unix.IN_OPEN|unix.IN_ACCESS|unix.IN_CLOSE_NOWRITE); err != nil {
			t.Fatal(err)
		}
	}
	opens := func() int {
		buf := make([]byte, 64<<10)
		n, err := unix.Read(in, buf)
		if err != nil {
			return 0
		}
		count := 0
		for off := 0; off+unix.SizeofInotifyEvent <= n; {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off])) //nolint:gosec // the kernel writes whole events
			count++
			off += unix.SizeofInotifyEvent + int(ev.Len)
		}
		return count
	}

	ctx := context.Background()
	for _, c := range append(system.All(), d) {
		_, _ = c.Collect(ctx, src)
	}
	if n := opens(); n != 0 {
		t.Errorf("a round of the collectors opened a decoy: %d events", n)
	}

	ch := make(chan Event, 256)
	f, err := NewFiles(root, src, ch)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	f.Set(Targets(nil, []string{"/srv/app/uploads"}))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	// Changed without being opened: truncate and chmod work by path.
	for _, p := range decoys[:2] {
		if err := os.Truncate(filepath.Join(root, p), 1); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	events := collect(t, ch, 2)
	if !has(events, ClassPrivilege, "write", "/etc/sudoers.d/90-backup") && !has(events, ClassPrivilege, "attrib", "/etc/sudoers.d/90-backup") {
		t.Errorf("the decoy's change is not reported: %+v", events)
	}
	if n := opens(); n != 0 {
		t.Errorf("the watcher opened a decoy: %d events", n)
	}
}
