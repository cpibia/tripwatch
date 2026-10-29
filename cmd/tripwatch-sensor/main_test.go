package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The bridges and virtual links of container runtimes carry the same addresses on every host and
// are left out; the machine's own interfaces are kept.
func TestContainerInterface(t *testing.T) {
	for name, want := range map[string]bool{"docker0": true, "br-3f2a9c1d": true, "veth9a1b2c": true, "cni0": true, "cali7f": true, "virbr0": true,
		"eth0": false, "ens5": false, "enp0s3": false, "wlan0": false, "bond0": false} {
		if got := containerInterface(name); got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
}

// Removal takes tripwatch's own directories whole, and only the bundle file from anywhere else.
func TestRemoveOwn(t *testing.T) {
	root := t.TempDir()
	own := filepath.Join(root, "etc", "tripwatch")
	shared := filepath.Join(root, "etc")
	if err := os.MkdirAll(own, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(own, "bundle.json"), filepath.Join(shared, "bundle.json"), filepath.Join(shared, "hosts")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeOwn(own, filepath.Join(own, "bundle.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Error("tripwatch's own directory was kept")
	}
	if err := removeOwn(shared, filepath.Join(shared, "bundle.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(shared, "hosts")); err != nil {
		t.Error("a directory not tripwatch's own was removed")
	}
	if _, err := os.Stat(filepath.Join(shared, "bundle.json")); !os.IsNotExist(err) {
		t.Error("the bundle was kept")
	}
}

// A snapshot cut short by the sensor's stop is not sealed: no envelope reaches the transport,
// which this test does not even provide.
func TestSnapshotCutShortIsNotSent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (sensor{root: t.TempDir()}).sendSnapshot(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the stop's cancellation", err)
	}
}
