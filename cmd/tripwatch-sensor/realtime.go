package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cpibia/tripwatch/internal/collector"
	"github.com/cpibia/tripwatch/internal/collector/system"
	"github.com/cpibia/tripwatch/internal/collector/web"
	"github.com/cpibia/tripwatch/internal/protocol"
	"github.com/cpibia/tripwatch/internal/transport"
	"github.com/cpibia/tripwatch/internal/watch"
)

// realtime runs the watchers between snapshots. Where the kernel lacks an interface or the
// sensor a capability, it goes on with snapshots alone and says so in each of them.
type realtime struct {
	files  *watch.Files
	execs  *watch.Execs
	mu     sync.Mutex
	issues []string
	// sent is closed once the batcher has sent what was queued at the stop.
	sent chan struct{}
}

// startRealtime starts the watchers; send gets each batch and returns an error only when the
// batch has to be sent again.
func (s sensor) startRealtime(ctx context.Context, log *slog.Logger, send func(context.Context, []byte) error) *realtime {
	src := collector.NewSource(s.root)
	events := make(chan watch.Event, 2048)
	r := &realtime{}
	var err error
	if r.files, err = watch.NewFiles(s.root, src, events); err != nil {
		r.fail("files", err)
		log.Warn("file changes are seen only in snapshots", "err", err)
	} else {
		r.files.Set(watch.Targets(nil, nil))
		go r.run(ctx, log, "files", r.files.Run)
	}
	if r.execs, err = watch.NewExecs(src, events); err != nil {
		r.fail("processes", err)
		log.Warn("process starts are seen only in snapshots", "err", err)
	} else {
		if r.execs.CapDropErr != nil {
			r.fail("processes", errors.New("CAP_NET_ADMIN could not be given up after subscribing: "+r.execs.CapDropErr.Error()))
		}
		go r.run(ctx, log, "processes", r.execs.Run)
	}
	if r.files == nil && r.execs == nil {
		return r
	}
	b := &watch.Batcher{
		In:             events,
		Send:           send,
		Lost:           r.lost,
		PackageManager: func() bool { return watch.PackageManagerRunning(src.FS) },
		Done:           make(chan struct{}),
	}
	r.sent = b.Done
	go b.Run(ctx)
	return r
}

// drained waits, within a bound, for the last events to go out: the stop event has to follow
// them in the chain.
func (r *realtime) drained() {
	if r == nil || r.sent == nil {
		return
	}
	select {
	case <-r.sent:
	case <-time.After(10 * time.Second):
	}
}

// sendEvents delivers a batch as an event envelope. A batch sealed but not delivered goes out
// before the next envelope, so only one never sealed is handed back.
func sendEvents(log *slog.Logger, client *transport.Client) func(context.Context, []byte) error {
	return func(ctx context.Context, payload []byte) error {
		err := client.Send(ctx, protocol.KindEvent, payload, time.Now())
		if errors.Is(err, transport.ErrNotSealed) {
			return err
		}
		if err != nil && ctx.Err() == nil {
			log.Warn("events not delivered yet, they go out before the next envelope", "err", err)
		}
		return nil
	}
}

func (r *realtime) run(ctx context.Context, log *slog.Logger, name string, run func(context.Context) error) {
	if err := run(ctx); err != nil && ctx.Err() == nil {
		r.fail(name, err)
		log.Error("real-time watcher stopped", "watcher", name, "err", err)
		r.mu.Lock()
		if name == "files" {
			r.files = nil
		} else {
			r.execs = nil
		}
		r.mu.Unlock()
	}
}

func (r *realtime) fail(name string, err error) {
	r.mu.Lock()
	r.issues = append(r.issues, name+": "+err.Error())
	r.mu.Unlock()
}

func (r *realtime) lost() (dropped, skipped int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.files != nil {
		dropped += r.files.Dropped.Load()
	}
	if r.execs != nil {
		dropped += r.execs.Dropped.Load()
		skipped = r.execs.Skipped.Load()
	}
	return dropped, skipped
}

// update points the watchers at what the latest snapshot found: the accounts' homes, the web
// applications' upload directories, the users the web server runs as.
func (r *realtime) update(snap collector.Snapshot) {
	var accounts system.AccountsResult
	var processes system.ProcessesResult
	var site web.Result
	_ = json.Unmarshal(snap.Results["accounts"], &accounts)
	_ = json.Unmarshal(snap.Results["processes"], &processes)
	_ = json.Unmarshal(snap.Results["web"], &site)
	homes := make([]watch.Home, 0, len(accounts.Accounts))
	for _, a := range accounts.Accounts {
		homes = append(homes, watch.Home{User: a.Name, Dir: a.Home})
	}
	var uploads []string
	for _, app := range site.Apps {
		uploads = append(uploads, app.UploadDirs...)
	}
	r.mu.Lock()
	files, execs := r.files, r.execs
	r.mu.Unlock()
	if files != nil {
		files.Set(watch.Targets(homes, uploads))
	}
	if execs != nil {
		execs.SetWebUsers(watch.WebUsers(&accounts, &processes))
		homes := make(map[int]string, len(accounts.Accounts))
		for _, a := range accounts.Accounts {
			homes[a.UID] = a.Home
		}
		execs.SetHomes(homes)
		execs.SetUploads(uploads)
	}
}

func (r *realtime) status() *watch.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := &watch.Status{Files: r.files != nil, Processes: r.execs != nil, Issues: append([]string(nil), r.issues...)}
	if r.files != nil {
		st.Watches = r.files.Watches()
		st.Issues = append(st.Issues, r.files.Issues()...)
	}
	return st
}
