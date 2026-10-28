package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/buildinfo"
	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/selfupdate"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
)

const (
	updateOrderFile    = "update-order.json"
	uninstallOrderFile = "uninstall-order.json"
	uninstallUnit      = "tripwatch-sensor-uninstall"
	// updateUnit is the transient unit the update runs in: the package's scripts restart the
	// sensor's service, which would kill an installer running inside it.
	updateUnit = "tripwatch-sensor-update"
	// updateRetry is how long an order that did not install is left before it is tried again.
	updateRetry = time.Hour
)

type savedOrder struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// updateOrders acts on the update orders the verifier's answers carry: one signed by its CA for
// a newer release is handed to a transient unit, at most once an hour for the same version.
type updateOrders struct {
	ca         ed25519.PublicKey
	hostID     string
	bundlePath string
	stateDir   string
	log        *slog.Logger

	mu    sync.Mutex
	tried map[string]time.Time
	// warned rate-limits the warning for orders that do not verify.
	warned time.Time
}

func (u *updateOrders) receive(payload, signature string) {
	order, err := protocol.VerifyUpdate(payload, signature, u.ca)
	u.mu.Lock()
	defer u.mu.Unlock()
	if err != nil {
		if time.Since(u.warned) > updateRetry {
			u.warned = time.Now()
			u.log.Warn("update order refused", "err", err)
		}
		return
	}
	if !selfupdate.Newer(order.Version, buildinfo.Version) {
		return
	}
	if at, ok := u.tried[order.Version]; ok && time.Since(at) < updateRetry {
		return
	}
	u.tried[order.Version] = time.Now()
	if err := u.start(updateOrderFile, updateUnit, "-apply-update", payload, signature); err != nil {
		u.log.Error("ordered update not started", "version", order.Version, "err", err)
		return
	}
	u.log.Info("ordered update started", "version", order.Version, "unit", updateUnit)
}

// uninstall acts on the order a revoked host receives: signed by the CA and naming this host, it
// starts the removal of the sensor and its data, once.
func (u *updateOrders) uninstall(payload, signature string) {
	if _, err := protocol.VerifyUninstall(payload, signature, u.ca, u.hostID); err != nil {
		u.log.Warn("uninstall order refused", "err", err)
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if at, ok := u.tried["uninstall"]; ok && time.Since(at) < updateRetry {
		return
	}
	u.tried["uninstall"] = time.Now()
	if err := u.start(uninstallOrderFile, uninstallUnit, "-apply-uninstall", payload, signature); err != nil {
		u.log.Error("ordered removal not started", "err", err)
		return
	}
	u.log.Info("this host was revoked: removal started", "unit", uninstallUnit)
}

// start saves an order where only root reads it and runs it in a transient unit, outside the
// sensor's service, which verifies the order again before it acts.
func (u *updateOrders) start(file, unit, flag, payload, signature string) error {
	data, err := json.Marshal(savedOrder{Payload: payload, Signature: signature})
	if err != nil {
		return err
	}
	if err := pki.WriteFileAtomic(filepath.Join(u.stateDir, file), data); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	//nolint:gosec // our own executable and paths from the sensor's configuration
	out, err := exec.CommandContext(ctx, "systemd-run", "--unit="+unit, "--collect", "--quiet",
		exe, flag, "-bundle", u.bundlePath, "-state-dir", u.stateDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-run: %w: %s", err, out)
	}
	return nil
}

// applyOrderedUpdate installs the update the running sensor saved, after checking its signature
// against the CA of the bundle: the file sits in the state directory, and only an order signed
// by the verifier is acted on.
func applyOrderedUpdate(bundlePath, stateDir string) error {
	if bundlePath == "" || stateDir == "" {
		return errors.New("needs -bundle and -state-dir")
	}
	bundle, _, err := pki.LoadBundle(bundlePath)
	if err != nil {
		return err
	}
	ca, err := bundle.CAPublicKey()
	if err != nil {
		return err
	}
	path := filepath.Join(stateDir, updateOrderFile)
	data, err := os.ReadFile(path) //nolint:gosec // the state directory is the operator's configuration
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(path) }()
	var saved savedOrder
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	order, err := protocol.VerifyUpdate(saved.Payload, saved.Signature, ca)
	if err != nil {
		return err
	}
	u, err := newUpdater(stateDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	_, err = u.UpdateTo(ctx, order.Version, order.Sums)
	return err
}

// unitPaths are where the sensor's unit is installed: by the packages, or by hand next to a
// binary installed by hand.
var unitPaths = []string{"/etc/systemd/system/tripwatch-sensor.service", "/usr/lib/systemd/system/tripwatch-sensor.service", "/lib/systemd/system/tripwatch-sensor.service"}

// applyUninstall removes the sensor and its data on the order of the verifier that revoked this
// host, checked against the CA of the bundle: the package is purged, or the service, its unit
// and the binary removed by hand, then the bundle and the state. A directory is removed whole
// only when it is tripwatch's own; otherwise just the files.
func applyUninstall(bundlePath, stateDir string) error {
	if bundlePath == "" || stateDir == "" {
		return errors.New("needs -bundle and -state-dir")
	}
	bundle, _, err := pki.LoadBundle(bundlePath)
	if err != nil {
		return err
	}
	ca, err := bundle.CAPublicKey()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(stateDir, uninstallOrderFile)) //nolint:gosec // the state directory is the operator's configuration
	if err != nil {
		return err
	}
	var saved savedOrder
	if err := json.Unmarshal(data, &saved); err != nil {
		return err
	}
	if _, err := protocol.VerifyUninstall(saved.Payload, saved.Signature, ca, bundle.HostID); err != nil {
		return err
	}
	u, err := newUpdater(stateDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	switch u.Detect(ctx) {
	case selfupdate.Deb:
		err = u.Run(ctx, os.Stdout, "dpkg", "--purge", "tripwatch-sensor")
	case selfupdate.RPM:
		err = u.Run(ctx, os.Stdout, "rpm", "-e", "tripwatch-sensor")
	default:
		_ = u.Run(ctx, os.Stdout, "systemctl", "disable", "--now", "tripwatch-sensor")
		for _, p := range unitPaths {
			_ = os.Remove(p)
		}
		_ = u.Run(ctx, os.Stdout, "systemctl", "daemon-reload")
		err = os.Remove(u.Executable)
	}
	if err != nil {
		return fmt.Errorf("removing the sensor: %w", err)
	}
	return errors.Join(removeOwn(filepath.Dir(bundlePath), bundlePath), removeOwn(stateDir, ""))
}

// removeOwn removes dir whole when it is tripwatch's own directory, or else only file.
func removeOwn(dir, file string) error {
	if filepath.Base(filepath.Clean(dir)) == "tripwatch" && filepath.Dir(filepath.Clean(dir)) != "/" {
		return os.RemoveAll(dir)
	}
	if file != "" {
		return os.Remove(file)
	}
	return nil
}
