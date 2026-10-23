package analyze

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/cpibia/tripwatch/internal/verifier/store"
)

// PolicyChange is the complete diff behind a policy alert, whose detail shows only the first
// lines.
type PolicyChange struct {
	Lines []string
	// Since is when the snapshot compared with was taken.
	Since time.Time
}

// ErrNoPolicyDiff means the alert is not about a policy file, or its snapshots are gone.
var ErrNoPolicyDiff = errors.New("analyze: no policy diff for this alert")

// PolicyDiff rebuilds the diff of a policy alert from the newest snapshot kept as its evidence
// and the last earlier snapshot holding the policies.
func PolicyDiff(ctx context.Context, st *store.Store, a store.Alert) (PolicyChange, error) {
	var file string
	for _, prefix := range []string{"persistence-change:policy:", "persistence-change:policy-removed:"} {
		if rest, ok := strings.CutPrefix(a.Fingerprint, prefix); ok {
			file = rest[:max(strings.LastIndex(rest, "|"), 0)]
		}
	}
	if file == "" {
		return PolicyChange{}, ErrNoPolicyDiff
	}
	snap, err := st.LatestEvidence(ctx, a.ID)
	if err != nil {
		return PolicyChange{}, errors.Join(ErrNoPolicyDiff, err)
	}
	cur, err := Decode(snap.Payload)
	if err != nil || cur.Sudoers == nil {
		return PolicyChange{}, ErrNoPolicyDiff
	}
	for range maxBaseWalk {
		older, err := st.SnapshotBefore(ctx, snap.HostID, snap.ID)
		if err != nil {
			return PolicyChange{}, errors.Join(ErrNoPolicyDiff, err)
		}
		snap = older
		prev, err := Decode(snap.Payload)
		if err != nil || prev.Sudoers == nil {
			continue
		}
		return PolicyChange{Lines: diffLines(policyRules(prev, file), policyRules(cur, file)), Since: snap.TakenAt}, nil
	}
	return PolicyChange{}, ErrNoPolicyDiff
}

func policyRules(s State, file string) []string {
	for _, f := range s.Sudoers.Files {
		if f.Path == file {
			return f.Rules
		}
	}
	return nil
}
