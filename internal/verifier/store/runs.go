package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"
)

// SensorRun is what the verifier remembers of a host's sensor between a stop and the next start:
// the system boot and the version it last started in, and when it last said it was stopping
// (zero when it did not, or started again since).
type SensorRun struct {
	BootID    string
	Version   string
	StoppedAt time.Time
	// StopReason and Shutdown are what the sensor said as it stopped: "stopped", "updating" or
	// "package_removed", and whether systemd was shutting the system down.
	StopReason string
	Shutdown   bool
}

// startedBoot reads the boot out of a "Sensor started" alert, for hosts whose last start predates
// this record.
var startedBoot = regexp.MustCompile(`\(versione? ([0-9A-Za-z.+~-]+), (?:system boot|avvio di sistema) ([0-9a-f-]{8,64})\)`)

// Run returns what is known of the host's sensor run. A host never seen starting since this
// record exists falls back on its latest "Sensor started" alert.
func (s *Store) Run(ctx context.Context, host string) (SensorRun, error) {
	var r SensorRun
	var stopped int64
	err := s.db.QueryRowContext(ctx, `SELECT boot_id, version, stopped_at, stop_reason, shutdown FROM sensor_runs WHERE host_id = ?`, host).Scan(&r.BootID, &r.Version, &stopped, &r.StopReason, &r.Shutdown)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}
	r.StoppedAt = unix(stopped)
	if r.BootID != "" {
		return r, nil
	}
	var detail string
	err = s.db.QueryRowContext(ctx, `SELECT detail FROM alerts WHERE host_id = ? AND kind = 'sensor-event' AND fingerprint LIKE 'sensor:started:%'
		ORDER BY created_at DESC, id DESC LIMIT 1`, host).Scan(&detail)
	if errors.Is(err, sql.ErrNoRows) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if m := startedBoot.FindStringSubmatch(detail); m != nil {
		r.Version, r.BootID = m[1], m[2]
	}
	return r, nil
}

// Started records a start of the host's sensor and clears its stop.
func (s *Store) Started(ctx context.Context, host, bootID, version string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sensor_runs (host_id, boot_id, version, stopped_at, stop_reason, shutdown) VALUES (?, ?, ?, 0, '', 0)
		ON CONFLICT (host_id) DO UPDATE SET boot_id = excluded.boot_id, version = excluded.version, stopped_at = 0, stop_reason = '', shutdown = 0`,
		host, clip(bootID, 64), clip(version, 64))
	return err
}

// Stopped records that the host's sensor said it was stopping, why, and whether the system was
// shutting down.
func (s *Store) Stopped(ctx context.Context, host string, at time.Time, reason string, shutdown bool) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sensor_runs (host_id, stopped_at, stop_reason, shutdown) VALUES (?, ?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET stopped_at = excluded.stopped_at, stop_reason = excluded.stop_reason, shutdown = excluded.shutdown`,
		host, at.Unix(), clip(reason, 32), shutdown)
	return err
}
