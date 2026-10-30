package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/discovery"
	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/verifier/store"
)

var now = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type harness struct {
	t     *testing.T
	store *store.Store
	an    *Analyzer
	clock time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h := &harness{t: t, store: st, clock: now}
	h.an = &Analyzer{Store: st, Now: func() time.Time { return h.clock }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := st.Enroll(context.Background(), "web-01", make([]byte, 32), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	return h
}

// deliver stores an envelope of web-01 as the ingest would after verifying it.
func (h *harness) deliver(kind protocol.Kind, payload []byte) {
	h.t.Helper()
	ctx := context.Background()
	host, err := h.store.Host(ctx, "web-01")
	if err != nil {
		h.t.Fatal(err)
	}
	e := protocol.Envelope{HostID: "web-01", Kind: kind, Sequence: host.Chain.Sequence + 1, SentAt: h.clock, Payload: payload}
	if err := h.store.Accept(ctx, e, host.Chain, protocol.ChainState{Sequence: e.Sequence}, h.clock); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) open() map[string]store.Alert {
	h.t.Helper()
	all, err := h.store.Alerts(context.Background(), store.AlertFilter{Statuses: []string{store.StatusOpen}})
	if err != nil {
		h.t.Fatal(err)
	}
	out := map[string]store.Alert{}
	for _, a := range all {
		out[a.Fingerprint] = a
	}
	return out
}

const (
	rootOnly   = `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]}}}}`
	secondRoot = `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0},{"name":"backup","uid":0}]}}}}`
)

// The worker drains the queue in order: a second root account appearing in the newer snapshot
// raises a critical alert, and an undecodable snapshot raises its own.
func TestWorkerAnalysesQueuedSnapshots(t *testing.T) {
	h := newHarness(t)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, []byte("not gzip"))

	ctx, cancel := context.WithCancel(context.Background())
	wake := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { h.an.Worker(ctx, wake); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		pending, err := h.store.PendingSnapshots(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(pending) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still pending: %v", pending)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	alerts := h.open()
	if a, ok := alerts["accounts:uid0:backup"]; !ok || a.Severity != "critical" {
		t.Errorf("second root account: %+v", alerts)
	}
	if a, ok := alerts["snapshot:undecodable"]; !ok || a.Severity != "high" {
		t.Errorf("undecodable snapshot: %+v", alerts)
	}
}

func TestSilentSensor(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Enrolled an hour ago and never heard from.
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	if _, ok := h.open()["sensor:silent"]; !ok {
		t.Fatal("a host never heard from raised no silence alert")
	}

	// It reports again: the silence alert closes by itself, even though it is critical.
	h.deliver(protocol.KindHeartbeat, nil)
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	if _, ok := h.open()["sensor:silent"]; ok {
		t.Fatal("the silence alert stayed open after a heartbeat")
	}

	// Heartbeats keep coming but snapshots stop.
	h.clock = h.clock.Add(4 * time.Hour)
	h.deliver(protocol.KindHeartbeat, nil)
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	alerts := h.open()
	if _, ok := alerts["sensor:no-snapshots"]; !ok {
		t.Fatalf("heartbeats without snapshots raised nothing: %+v", alerts)
	}
	if _, ok := alerts["sensor:silent"]; ok {
		t.Fatal("a host sending heartbeats is reported silent")
	}

	// A stop on a running system leaves the silence critical.
	h.clock = h.clock.Add(time.Minute)
	h.deliver(protocol.KindHeartbeat, nil)
	if err := h.store.Stopped(ctx, "web-01", h.clock, "stopped", false); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(time.Hour)
	h.an.Silent(ctx, 3*time.Minute, 300*time.Hour)
	if got := h.open()["sensor:silent"].Severity; got != "critical" {
		t.Fatalf("silence after a stop on a running system: %q", got)
	}
	// A sensor that signed a shutdown is silent at medium for a day, then high.
	h.deliver(protocol.KindHeartbeat, nil)
	if err := h.store.Stopped(ctx, "web-01", h.clock, "stopped", true); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		after time.Duration
		want  string
	}{{8 * time.Hour, "medium"}, {20 * time.Hour, "high"}} {
		h.clock = h.clock.Add(step.after)
		h.an.Silent(ctx, 3*time.Minute, 300*time.Hour)
		if got := h.open()["sensor:silent"].Severity; got != step.want {
			t.Fatalf("silence %s after a clean stop: %q, want %q", step.after, got, step.want)
		}
	}
	h.deliver(protocol.KindHeartbeat, nil)
	h.an.Silent(ctx, 3*time.Minute, 300*time.Hour)

	// A revoked host is no longer watched.
	if err := h.store.Revoke(ctx, "web-01"); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(time.Hour)
	h.an.Silent(ctx, 3*time.Minute, 3*time.Hour)
	if a, ok := h.open()["sensor:silent"]; ok {
		t.Fatalf("revoked host reported silent: %+v", a)
	}
}

func TestFindingsPerSnapshotAreBounded(t *testing.T) {
	h := newHarness(t)
	accounts := `{"name":"root","uid":0}`
	for i := range 300 {
		accounts += fmt.Sprintf(`,{"name":"r%d","uid":0}`, i)
	}
	h.deliver(protocol.KindSnapshot, gz(t, `{"snapshot":{"results":{"accounts":{"accounts":[`+accounts+`]}}}}`))
	ids, _ := h.store.PendingSnapshots(context.Background(), 1)
	h.an.RunSnapshot(context.Background(), ids[0])
	// 200 findings of one rule reach the store: 100 alerts, then the rule's aggregate; plus the
	// summary of the 101 findings the snapshot cap dropped.
	alerts := h.open()
	if len(alerts) != store.MaxOpenPerGroup+2 {
		t.Fatalf("%d alerts, want %d", len(alerts), store.MaxOpenPerGroup+2)
	}
	if _, ok := alerts["snapshot:too-many-findings"]; !ok {
		t.Fatal("no summary of the dropped findings")
	}
}

// The snapshot that shows a change and the one before it survive the thinning.
func TestChangeKeepsBothSnapshots(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
	ids, _ := h.store.PendingSnapshots(ctx, 10)
	for _, id := range ids {
		h.an.RunSnapshot(ctx, id)
		_ = h.store.MarkAnalyzed(ctx, id)
	}
	// Three days of unchanged hourly snapshots push both past the dense window.
	for range 72 {
		h.clock = h.clock.Add(time.Hour)
		h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
		next, _ := h.store.PendingSnapshots(ctx, 10)
		for _, id := range next {
			h.an.RunSnapshot(ctx, id)
			_ = h.store.MarkAnalyzed(ctx, id)
		}
	}
	snaps, _ := h.store.LatestSnapshots(ctx, "web-01", 1000)
	kept := map[int64]bool{}
	for _, s := range snaps {
		kept[s.ID] = true
	}
	if !kept[ids[0]] || !kept[ids[1]] {
		t.Fatalf("the snapshots around the change were thinned: kept %d snapshots", len(snaps))
	}
}

// A log request repeated in every snapshot raises its alert once: only the snapshot where it
// started (and the one before) outlives the retention, not every snapshot that shows it again.
func TestRepeatedEventDoesNotKeepEverySnapshot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	payload := gz(t, `{"snapshot":{"results":{"weblog":{"events":[{"rule":"command_in_parameters","severity":"critical","log":"/var/log/nginx/access.log","attacker_controlled":{"request":"/index.php?c=id"}}]}}}}`)
	for range 40 {
		h.deliver(protocol.KindSnapshot, payload)
		ids, _ := h.store.PendingSnapshots(ctx, 10)
		for _, id := range ids {
			h.an.RunSnapshot(ctx, id)
			_ = h.store.MarkAnalyzed(ctx, id)
		}
		h.clock = h.clock.Add(24 * time.Hour)
	}
	snaps, _ := h.store.LatestSnapshots(ctx, "web-01", 1000)
	if len(snaps) > 33 {
		t.Fatalf("%d of 40 daily snapshots kept: the repeated event pins them past 30 days", len(snaps))
	}
}

// Anyone reaching the site can make every snapshot raise a new critical weblog alert: those are
// kept as evidence within the day's bound for their kind, not every snapshot for ever.
func TestAnonymousCriticalsKeepABoundedProof(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	for i := range 2 * 96 {
		h.clock = h.clock.Add(15 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, fmt.Sprintf(`{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]},"weblog":{"events":[{"rule":"command_in_parameters","severity":"critical","log":"/l","attacker_controlled":{"request":"/x%d.php?cmd=id"}}]}}}}`, i)))
		h.analyse()
	}
	h.clock = h.clock.Add(40 * 24 * time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	snaps, _ := h.store.SnapshotHeads(ctx, "web-01", 1000)
	// Two days of proofs, each with the snapshot before it, the baseline and the last one.
	if limit := 2*2*maxEvidencePerDay + 4; len(snaps) > limit {
		t.Fatalf("%d snapshots kept after 40 days, at most %d: every anonymous critical keeps its snapshot", len(snaps), limit)
	}
}

// An alert made to reopen at every snapshot keeps one proof a day, not one per snapshot.
func TestFlappingAlertKeepsOneProofADay(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := range 48 {
		payload := rootOnly
		if i%2 == 1 {
			payload = secondRoot
		}
		h.deliver(protocol.KindSnapshot, gz(t, payload))
		ids, _ := h.store.PendingSnapshots(ctx, 10)
		for _, id := range ids {
			h.an.RunSnapshot(ctx, id)
			_ = h.store.MarkAnalyzed(ctx, id)
		}
		// Resolved by hand each time, so the next snapshot with it reopens the alert.
		alerts, _ := h.store.Alerts(ctx, store.AlertFilter{HostID: "web-01", Statuses: []string{store.StatusOpen}})
		for _, a := range alerts {
			_ = h.store.Resolve(ctx, a.ID, "ops@example.net", h.clock)
		}
		h.clock = h.clock.Add(time.Hour)
	}
	// Three days later the thinning runs: of the 48 hourly snapshots only the proofs (one a
	// day with the snapshot before it), the last of each day and the baseline remain.
	h.clock = h.clock.Add(72 * time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	snaps, _ := h.store.SnapshotHeads(ctx, "web-01", 100)
	if len(snaps) > 10 {
		t.Fatalf("%d snapshots kept: a flapping alert keeps one per reopening", len(snaps))
	}
}

func (h *harness) analyse() {
	h.t.Helper()
	ctx := context.Background()
	ids, _ := h.store.PendingSnapshots(ctx, 10)
	for _, id := range ids {
		h.an.RunSnapshot(ctx, id)
		_ = h.store.MarkAnalyzed(ctx, id)
	}
}

func rootWith(name, home string) string {
	return `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0},{"name":"` + name + `","uid":0,"home":"` + home + `"}]}}}}`
}

// Noise anyone can raise uses up only its own kind's daily bound: an alert only root can cause,
// arriving after it, is still kept as evidence.
func TestRootAlertKeptAfterTheNoise(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	for i := range 40 {
		h.clock = h.clock.Add(10 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, fmt.Sprintf(`{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]},"weblog":{"events":[{"rule":"command_in_parameters","severity":"critical","log":"/l","attacker_controlled":{"request":"/x%d.php?cmd=id"}}]}}}}`, i)))
		h.analyse()
	}
	day := now.Truncate(24 * time.Hour)
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, gz(t, secondRoot))
	h.analyse()
	id, _ := h.store.AlertID(ctx, "web-01", "accounts:uid0:backup")
	if ok, _ := h.store.HasEvidenceSince(ctx, id, criticalDigest(t, h, id), day); !ok {
		t.Fatal("a root alert after the noise was not kept as evidence")
	}
}

// criticalDigest is the digest the analyser gave the alert's current content.
func criticalDigest(t *testing.T, h *harness, id int64) string {
	t.Helper()
	a, err := h.store.Alert(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(a.Severity + "\x00" + a.Detail))
	return hex.EncodeToString(sum[:8])
}

// A harmless decoy raised early does not take the day's proof from different content raised
// later under the same alert.
func TestDecoyDoesNotTakeTheDaysProof(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootWith("backup", "/decoy")))
	h.analyse()
	id, _ := h.store.AlertID(ctx, "web-01", "accounts:uid0:backup")
	_ = h.store.Resolve(ctx, id, "ops@example.net", h.clock)
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootWith("backup", "/var/lib/real")))
	h.analyse()
	genuine, _ := h.store.SnapshotHeads(ctx, "web-01", 1)
	// A later snapshot the same day, so the genuine one is not kept just as the day's last.
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootWith("backup", "/var/lib/real")))
	h.analyse()

	h.clock = h.clock.Add(72 * time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	snaps, _ := h.store.SnapshotHeads(ctx, "web-01", 100)
	if !slices.ContainsFunc(snaps, func(s store.SnapshotHead) bool { return s.ID == genuine[0].ID }) {
		t.Fatal("the snapshot with the real content went with the thinning")
	}
}

// A critical log alert, which anyone can raise with one request, is bounded like any other
// kind: a new script each snapshot does not keep every snapshot.
func TestAnonymousCriticalAlertsAreBounded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := range 40 {
		h.clock = h.clock.Add(10 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, fmt.Sprintf(`{"snapshot":{"results":{"weblog":{"events":[{"rule":"command_in_parameters","severity":"critical","log":"/var/log/nginx/access.log","attacker_controlled":{"request":"/x%d.php?cmd=id"}}]}}}}`, i)))
		h.analyse()
	}
	kept, _ := h.store.EvidenceSnapshotsSince(ctx, "web-01", now.Truncate(24*time.Hour))
	if kept["weblog|critical"] == 0 || kept["weblog|critical"] > maxEvidencePerDay+1 {
		t.Fatalf("%d snapshots kept as evidence of anonymous critical alerts", kept["weblog|critical"])
	}
}

// A user's own keys, however many, do not crowd out a key root adds: it gets its own alert and
// its evidence is kept.
func TestUserKeysDoNotHideRootKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	keys := func(n int, root bool) string {
		var parts []string
		for i := range n {
			parts = append(parts, fmt.Sprintf(`{"user":"www-data","file":"/var/www/.ssh/authorized_keys","type":"ssh-ed25519","fingerprint":"SHA256:w%d"}`, i))
		}
		if root {
			parts = append(parts, `{"user":"root","file":"/root/.ssh/authorized_keys","type":"ssh-ed25519","fingerprint":"SHA256:r"}`)
		}
		return `{"snapshot":{"results":{"ssh":{"keys":[` + strings.Join(parts, ",") + `]}}}}`
	}
	h.deliver(protocol.KindSnapshot, gz(t, keys(0, false)))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, keys(150, false)))
	h.analyse()
	h.clock = h.clock.Add(time.Hour)
	h.deliver(protocol.KindSnapshot, gz(t, keys(150, true)))
	h.analyse()
	id, err := h.store.AlertID(ctx, "web-01", "ssh-change:key:root|SHA256:r")
	if err != nil {
		t.Fatal("the root key has no alert of its own")
	}
	if ok, _ := h.store.HasEvidenceSince(ctx, id, criticalDigest(t, h, id), now.Truncate(24*time.Hour)); !ok {
		t.Fatal("the root key's snapshot is not kept as evidence")
	}
}

// Medium noise uses up only the medium budget of its kind: a critical alert of the same kind
// later in the day is still kept.
func TestCriticalHasItsOwnBudget(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	web := func(findings string) string {
		return `{"snapshot":{"results":{"web":{"apps":[{"path":"/var/www/app","findings":[` + findings + `]}]}}}}`
	}
	h.deliver(protocol.KindSnapshot, gz(t, web("")))
	h.analyse()
	for i := range 30 {
		h.clock = h.clock.Add(10 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, web(fmt.Sprintf(`{"kind":"hidden_in_data_dir","path":"/var/www/app/up/.x%d","sha256":"h%d"}`, i, i))))
		h.analyse()
	}
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, gz(t, web(`{"kind":"script_in_upload_dir","path":"/var/www/app/up/shell.php","sha256":"s"}`)))
	h.analyse()
	id, err := h.store.AlertID(ctx, "web-01", "web:script_in_upload_dir:/var/www/app/up/shell.php")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.store.HasEvidenceSince(ctx, id, criticalDigest(t, h, id), now.Truncate(24*time.Hour)); !ok {
		t.Fatal("the critical web alert lost its evidence to medium noise")
	}
}

// A collector that failed in the previous snapshot does not make the next one the reference:
// the change is compared with the last snapshot where that collector answered.
func TestChangeAfterFailedCollectorIsCompared(t *testing.T) {
	h := newHarness(t)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, gz(t, `{"snapshot":{"results":{},"errors":{"accounts":"timeout"}}}`))
	h.analyse()
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, gz(t, `{"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0},{"name":"alice","uid":1000}]}}}}`))
	h.analyse()
	if _, ok := h.open()["accounts-change:new:alice"]; !ok {
		t.Fatalf("change after a failed collector not raised: %v", h.open())
	}
}

// A kind of database objects not read in one snapshot, a table locked while a row is added to it,
// is compared with the last snapshot that read it: the row does not join the baseline unseen.
func TestObjectKindNotReadIsComparedLater(t *testing.T) {
	h := newHarness(t)
	shop := func(read, objects string) []byte {
		return gz(t, `{"snapshot":{"results":{"apps":{"apps":[{"path":"/var/www/shop","framework":"magento2","db_objects":[`+objects+`],"db_objects_read":[`+read+`]}]}}}}`)
	}
	h.deliver(protocol.KindSnapshot, shop(`"trigger","admin_token"`, `{"kind":"admin_token","id":"9","target":"integration 3","hash":"k1"}`))
	h.analyse()
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, shop(`"trigger"`, ``))
	h.analyse()
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, shop(`"trigger","admin_token"`, `{"kind":"admin_token","id":"9","target":"integration 3","hash":"k1"},{"kind":"admin_token","id":"10","target":"administrator 1","hash":"k2"}`))
	h.analyse()
	var raised []string
	for fp := range h.open() {
		if strings.Contains(fp, "object:") {
			raised = append(raised, fp)
		}
	}
	if len(raised) != 1 || !strings.Contains(raised[0], ":admin_token:10:") {
		t.Fatalf("object alerts = %v", raised)
	}
}

// A collector that keeps failing is a high alert that stays open after it answers again, and
// one silent past the walked history says its changes cannot be compared.
func TestCollectorFailingForLong(t *testing.T) {
	h := newHarness(t)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	failed := `{"snapshot":{"results":{},"errors":{"accounts":"timeout"}}}`
	for range maxBaseWalk {
		h.clock = h.clock.Add(10 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, failed))
		h.analyse()
	}
	if a, ok := h.open()["sensor:error-persistent:accounts"]; !ok || a.Severity != "high" {
		t.Fatalf("persistent failure not raised: %v", h.open())
	}
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, gz(t, rootOnly))
	h.analyse()
	open := h.open()
	if _, ok := open["sensor:error-persistent:accounts"]; !ok {
		t.Fatal("persistent failure closed when the collector answered")
	}
	if _, ok := open["sensor:baseline-lost:accounts"]; !ok {
		t.Fatalf("lost baseline not raised: %v", open)
	}
}

// The alert detail shows the first lines of a policy change; the complete diff is kept with it.
func TestPolicyDiffIsComplete(t *testing.T) {
	h := newHarness(t)
	policy := func(sum string, rules []string) []byte {
		data, _ := json.Marshal(rules)
		return gz(t, `{"snapshot":{"results":{"sudoers":{"files":[{"path":"/etc/sudoers.d/x","sha256":"`+sum+`","rules":`+string(data)+`}]}}}}`)
	}
	h.deliver(protocol.KindSnapshot, policy("a", []string{"Defaults env_reset"}))
	h.analyse()
	rules := []string{"Defaults env_reset"}
	for i := range 60 {
		rules = append(rules, fmt.Sprintf("Cmnd_Alias C%d = /bin/true", i))
	}
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, policy("b", rules))
	h.analyse()
	a, ok := h.open()["persistence-change:policy:/etc/sudoers.d/x|b"]
	if !ok {
		t.Fatalf("policy change not raised: %v", h.open())
	}
	lines, _, err := h.store.AlertDiff(context.Background(), a.ID)
	if got := strings.Split(lines, "\n"); err != nil || len(got) != 60 || got[0] != "+ Cmnd_Alias C0 = /bin/true" {
		t.Fatalf("diff = %d lines, %v", len(got), err)
	}
}

// A snapshot's facts carry the sensor's system block and what the collectors counted.
func TestFactsFromSnapshot(t *testing.T) {
	st := State{TakenAt: time.Unix(1729670400, 0).UTC(),
		Environment: discovery.Environment{Kind: discovery.KindHost, System: &discovery.System{OS: "Amazon Linux 2023", Kernel: "6.1.112", Arch: "amd64", SensorVersion: "0.1.8", CPUs: 2}},
		Packages:    &system.PackagesResult{Manager: system.ManagerRpm, Packages: 412},
		Sockets:     &system.SocketsResult{Sockets: []system.Socket{{Proto: "tcp", Local: "0.0.0.0:22", State: "listen"}, {Proto: "tcp", Local: "0.0.0.0:22", State: "listen"}, {Proto: "tcp", Local: "10.0.0.5:51234", State: "established"}}},
		Web:         &web.Result{Apps: []web.AppReport{{Application: discovery.Application{Path: "/srv/www/blog", Framework: "wordpress", Version: "6.6.2"}}}},
	}
	f := Facts(st)
	if f.OS != "Amazon Linux 2023" || f.SensorVersion != "0.1.8" || f.CPUs != 2 || f.PackageManager != system.ManagerRpm || f.Packages != 412 ||
		f.Listening != 1 || len(f.Apps) != 1 || f.Apps[0].Framework != "wordpress" || f.Environment != "host" || !f.SeenAt.Equal(st.TakenAt) {
		t.Errorf("facts = %+v", f)
	}
}

// Applications a site serves come first in the facts: however many old releases and projects
// lie on disk, they cannot push the served ones past the bound.
func TestFactsKeepServedAppsFirst(t *testing.T) {
	var reports []web.AppReport
	for i := range maxAppFacts + 5 {
		reports = append(reports, web.AppReport{Application: discovery.Application{Path: fmt.Sprintf("/srv/releases/%02d", i), Framework: "wordpress"}})
	}
	reports = append(reports, web.AppReport{Application: discovery.Application{Path: "/srv/site", Framework: "wordpress", Version: "6.6.2", Sites: []string{"www.example.com"}}})
	f := Facts(State{Web: &web.Result{Apps: reports}})
	if len(f.Apps) != maxAppFacts || f.Apps[0].Path != "/srv/site" || len(f.SortedApps()) != maxAppFacts {
		t.Errorf("apps = %d, first %+v", len(f.Apps), f.Apps[0])
	}
}

// A collector that an updated sensor brings has nothing to compare with in the snapshots of the
// older version: that is no lost baseline.
func TestNewCollectorAfterAnUpdate(t *testing.T) {
	h := newHarness(t)
	old := `{"environment":{"system":{"sensor_version":"0.1.13"}},"snapshot":{"results":{}}}`
	for range maxBaseWalk + 1 {
		h.clock = h.clock.Add(10 * time.Minute)
		h.deliver(protocol.KindSnapshot, gz(t, old))
		h.analyse()
	}
	h.clock = h.clock.Add(10 * time.Minute)
	h.deliver(protocol.KindSnapshot, gz(t, `{"environment":{"system":{"sensor_version":"0.1.14"}},"snapshot":{"results":{"accounts":{"accounts":[{"name":"root","uid":0}]}}}}`))
	h.analyse()
	if _, ok := h.open()["sensor:baseline-lost:accounts"]; ok {
		t.Fatalf("a collector new with the sensor's version raised a lost baseline: %v", h.open())
	}
}

// A hook change a real-time event already reported is not raised again by the snapshot that
// shows it; one no event reported is.
func TestHookSeenInRealTimeIsNotRepeated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	snap := func(taken time.Time, files string) string {
		return `{"snapshot":{"taken_at":"` + taken.Format(time.RFC3339) + `","results":{"hooks":{"files":[` + files + `]}}}}`
	}
	old := h.clock.Add(-48 * time.Hour).Format(time.RFC3339)
	h.deliver(protocol.KindSnapshot, gz(t, snap(h.clock, `{"path":"/etc/profile.d/a.sh","sha256":"aaaa","mtime":"`+old+`"},{"path":"/etc/profile.d/b.sh","sha256":"bbbb","mtime":"`+old+`"}`)))
	h.clock = h.clock.Add(30 * time.Minute)
	data := []byte(`{"class":"hook","op":"write","path":"/etc/profile.d/a.sh","sha256":"a222"}`)
	if _, err := h.store.AddEvents(ctx, []store.Event{{HostID: "web-01", Seq: 1, At: h.clock, Class: "hook", Op: "write", Path: "/etc/profile.d/a.sh", Data: data}}, h.clock); err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(30 * time.Minute)
	recent := h.clock.Add(-10 * time.Minute).Format(time.RFC3339)
	h.deliver(protocol.KindSnapshot, gz(t, snap(h.clock, `{"path":"/etc/profile.d/a.sh","sha256":"a222","mtime":"`+recent+`"},{"path":"/etc/profile.d/b.sh","sha256":"b222","mtime":"`+recent+`"}`)))
	ids, _ := h.store.PendingSnapshots(ctx, 10)
	for _, id := range ids {
		h.an.RunSnapshot(ctx, id)
		_ = h.store.MarkAnalyzed(ctx, id)
	}
	open := h.open()
	if _, ok := open["persistence-change:hook:/etc/profile.d/a.sh|a222"]; ok {
		t.Error("the change reported in real time is raised again")
	}
	if _, ok := open["persistence-change:hook:/etc/profile.d/b.sh|b222"]; !ok {
		t.Errorf("the change no event reported is not raised: %v", slices.Collect(maps.Keys(open)))
	}
}

// What a collector could not do reaches the operator: one low alert per collector, naming its
// issues within a bound, the rest counted.
func TestCollectorIssuesRaiseAnAlert(t *testing.T) {
	issues := make([]string, maxCollectorIssues+5)
	for i := range issues {
		issues[i] = fmt.Sprintf("/var/www/shop/f%d.js: strings built past what the skimmer search follows", i)
	}
	raw, err := json.Marshal(map[string]any{"snapshot": map[string]any{"results": map[string]any{
		"web":        map[string]any{"issues": issues},
		"kernel":     map[string]any{"issues": []string{"hidden process search stopped at PID 9 of 99: 4 runs have not probed every PID"}},
		"privileged": map[string]any{"issues": []string{"/mnt/share: nfs4 network filesystem mounted without nosuid, not walked"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := Decode(gz(t, string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var got []Finding
	for _, f := range Evaluate(nil, st) {
		if f.Kind == "collector-issues" {
			got = append(got, f)
		}
	}
	if len(got) != 2 || got[0].Severity != "low" || got[0].Fingerprint != "collector-issues:kernel" || !strings.Contains(got[1].Detail, "and 5 more") {
		t.Errorf("findings = %+v", got)
	}
	f := Facts(st)
	if len(f.Limits) != 3 || f.Limits[1].Collector != "privileged" || len(f.Limits[1].Notes) != 1 || len(f.Limits[1].Incomplete) != 0 || f.Limits[2].More != 5 {
		t.Errorf("limits = %+v", f.Limits)
	}
}

// The sensor keeps findings past its bound by the severity the verifier gives them: the two
// orders must agree for every kind.
func TestFindingRankMatchesSeverity(t *testing.T) {
	rank := map[string]int{"critical": 3, "high": 2, "medium": 1, "": 0}
	for _, kind := range []string{web.KindSkimmer, web.KindActiveSVG, web.KindScriptInUploads, web.KindCodeInUploads, web.KindPolyglotImage, web.KindSignature,
		web.KindHiddenScript, web.KindHiddenInData, web.KindEncodedBlob, web.KindSuspiciousSymlink, web.KindExternalSymlink, web.KindAppInData, web.KindOverrideInData, web.KindCodeInData} {
		for _, sigs := range [][]string{nil, {"eval"}, {"obfuscation"}, {"handler_directive"}} {
			sev, _ := webFinding(web.Finding{Kind: kind, Signatures: sigs})
			if got := web.FindingRank(kind, sigs); got != rank[sev] {
				t.Errorf("%s %v: rank %d, severity %q", kind, sigs, got, sev)
			}
		}
	}
}

// Notes, skipped by design or explained, stay off the alert; an issue of work left undone stays
// one even when a path an attacker names imitates a note.
func TestIssueNotes(t *testing.T) {
	for issue, note := range map[string]bool{
		"hidden process search stopped at PID 2035712 of 4194304":                                            true,
		"hidden process search stopped at PID 2035712 of 4194304: 4 runs have not probed every PID":          false,
		"/home/u/dav: fuse network filesystem, not scanned":                                                  true,
		"/mnt/share: nfs4 network filesystem mounted without nosuid, not walked":                             true,
		`/var/www/up/a.php: PHP in an upload directory is code: word "use" at 6`:                             true,
		"/var/www/up/a.php: PHP in an upload directory is code: no <?php at the start":                       true,
		`/var/www/x: PHP in an upload directory is code: word "a" at 1: not fully searched for code: budget`: false,
		"/var/www/x: fuse network filesystem, not scanned/a.js: not read for skimmers, budget spent":         false,
		"/var/www/shop: content not scanned: context deadline exceeded":                                      false,
		"/var/www/shop: 5 findings that raise no alert left out past 200":                                    true,
		"/var/www/shop: 1 findings that raise an alert left out past 1000, the least severe first":           false,
	} {
		if issueNote(issue) != note {
			t.Errorf("%q: note %v", issue, !note)
		}
	}
}
