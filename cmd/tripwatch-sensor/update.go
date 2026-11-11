package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/buildinfo"
	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/provenance"
	"github.com/cpibia/tripwatch/internal/selfupdate"
	"github.com/cpibia/tripwatch/internal/transport"
	"github.com/cpibia/tripwatch/internal/verifier/pki"
)

const (
	updateOrderFile = "update-order.json"
	// refusedUpdateFile holds an update refused on evidence until the running sensor reports it:
	// the refusal may happen outside the service (-apply-update, -update), away from the chain.
	refusedUpdateFile  = "update-refused.json"
	maxRefusedUpdate   = 4 << 10
	maxRefusalReason   = 1 << 10
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
	recordRefusal(stateDir, err)
	return err
}

type refusedUpdate struct {
	Version string `json:"version"`
	Reason  string `json:"reason"`
}

// recordRefusal leaves an update refused on evidence for the running sensor to report. A
// failure to reach the release is not recorded: the update is simply tried again later.
func recordRefusal(stateDir string, err error) {
	var r *selfupdate.RejectedError
	if stateDir == "" || !errors.As(err, &r) {
		return
	}
	reason := r.Err.Error()
	if len(reason) > maxRefusalReason {
		reason = reason[:maxRefusalReason]
	}
	data, mErr := json.Marshal(refusedUpdate{Version: r.Version, Reason: reason})
	if mErr == nil {
		mErr = pki.WriteFileAtomic(filepath.Join(stateDir, refusedUpdateFile), data)
	}
	if mErr != nil {
		fmt.Fprintln(os.Stderr, "refused update not recorded:", mErr)
	}
}

// reportRefusedUpdate sends a refusal left in the state directory as a signed event, and removes
// it once the event is sealed: from then on the chain delivers it.
func reportRefusedUpdate(ctx context.Context, log *slog.Logger, client *transport.Client, stateDir string) {
	if stateDir == "" {
		return
	}
	path := filepath.Join(stateDir, refusedUpdateFile)
	f, err := os.Open(path) //nolint:gosec // the state directory is the operator's configuration
	if err != nil {
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRefusedUpdate+1))
	_ = f.Close()
	var r refusedUpdate
	if err != nil || len(data) > maxRefusedUpdate || json.Unmarshal(data, &r) != nil {
		log.Warn("unreadable record of a refused update removed", "err", err)
		_ = os.Remove(path)
		return
	}
	payload, _ := json.Marshal(map[string]string{"event": "update_refused", "version": r.Version, "reason": r.Reason})
	if err := client.Send(ctx, protocol.KindEvent, payload, time.Now()); err != nil {
		if errors.Is(err, transport.ErrNotSealed) {
			log.Warn("refused update not reported yet", "version", r.Version, "err", err)
			return
		}
		log.Warn("refused update reported, delivery pending", "version", r.Version, "err", err)
	}
	log.Warn("update refused: its provenance did not verify", "version", r.Version, "reason", r.Reason)
	_ = os.Remove(path)
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
	bundle, key, err := pki.LoadBundle(bundlePath)
	if err != nil {
		return err
	}
	// The client certificate is loaded before the purge, which may take the renewed one away.
	identity, err := bundle.ClientIdentity(stateDir)
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
	reportRemoval(ctx, bundle, key, identity)
	return errors.Join(removeOwn(filepath.Dir(bundlePath), bundlePath), removeOwn(stateDir, ""))
}

// reportRemoval tells the verifier the removal took place, best effort: the sensor is gone either
// way, and the verifier then shows the removal as not confirmed.
func reportRemoval(ctx context.Context, bundle pki.Bundle, key ed25519.PrivateKey, identity *pki.Identity) {
	payload, sig, err := protocol.SignRemoval(protocol.RemovalReport{HostID: bundle.HostID, Version: buildinfo.Version, RemovedAt: time.Now().UTC()}, key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "removal not reported:", err)
		return
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: identity.TLS()}, Timeout: 30 * time.Second}
	if err := transport.ReportRemoval(ctx, hc, bundle.VerifierURL, payload, sig); err != nil {
		fmt.Fprintln(os.Stderr, "removal not reported:", err)
	}
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

// verifyRelease checks release files against the release's provenance bundle exactly as an
// update does, offline: the release workflow runs it before publishing, operators may too.
func verifyRelease(out io.Writer, v *provenance.Verifier, bundlePath, version string, files []string) error {
	if version == "" || len(files) == 0 {
		return errors.New("needs -release VERSION and the release files to check")
	}
	bundle, err := readBounded(bundlePath, provenance.MaxBundleSize+1)
	if err != nil {
		return err
	}
	subjects, err := v.Verify(bundle, version)
	if err != nil {
		return err
	}
	for _, path := range files {
		name := filepath.Base(path)
		want, ok := subjects[name]
		if !ok {
			return fmt.Errorf("%s: not attested by the provenance of %s", name, version)
		}
		f, err := os.Open(path) //nolint:gosec // files named on the command line
		if err != nil {
			return err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		_ = f.Close()
		if err != nil {
			return err
		}
		if !bytes.Equal(h.Sum(nil), want[:]) {
			return fmt.Errorf("%s: SHA-256 is not the attested one", name)
		}
		_, _ = fmt.Fprintf(out, "%s: built by %s at v%s\n", name, provenance.Workflow, version)
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a path named on the command line
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}
