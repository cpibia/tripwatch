// Package protocol defines the signed, hash-chained envelopes a sensor sends to the verifier.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"sync"
	"time"
)

// Kind identifies what an envelope carries.
type Kind string

const (
	KindHeartbeat Kind = "heartbeat"
	KindEvent     Kind = "event"
	KindSnapshot  Kind = "snapshot"
)

const signingDomain = "tripwatch/envelope/v1"

// Envelope is the unit a sensor sends to the verifier. Envelopes from one host form a hash
// chain: each carries the digest of its predecessor, so a dropped, reordered or replayed
// envelope is detectable.
//
// Payload is raw bytes rather than embedded JSON because encoding/json rewrites embedded
// JSON (compaction, HTML escaping), which would invalidate the signature.
type Envelope struct {
	HostID    string    `json:"host_id"`
	Sequence  uint64    `json:"seq"`
	PrevHash  []byte    `json:"prev_hash,omitempty"`
	SentAt    time.Time `json:"sent_at"`
	Kind      Kind      `json:"kind"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"sig"`
}

// Digest returns the hash that is signed and that the next envelope references as PrevHash.
func (e *Envelope) Digest() []byte {
	h := sha256.New()
	writeField(h, []byte(signingDomain))
	writeField(h, []byte(e.HostID))
	writeField(h, binary.BigEndian.AppendUint64(nil, e.Sequence))
	writeField(h, e.PrevHash)
	writeField(h, []byte(e.SentAt.UTC().Format(time.RFC3339Nano)))
	writeField(h, []byte(e.Kind))
	writeField(h, e.Payload)
	return h.Sum(nil)
}

// Length-prefixing keeps field boundaries unambiguous, so bytes cannot be shifted between
// adjacent fields without changing the digest.
func writeField(h hash.Hash, b []byte) {
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
	h.Write(b)
}

// ChainState is the position in a host's chain: the last sequence number and its digest.
// The zero value is the start of a new chain.
type ChainState struct {
	Sequence   uint64 `json:"seq"`
	LastDigest []byte `json:"last_digest,omitempty"`
}

// Sealer signs envelopes for one host and advances its chain. It is safe for concurrent use.
type Sealer struct {
	mu     sync.Mutex
	hostID string
	key    ed25519.PrivateKey
	state  ChainState
}

// NewSealer resumes the chain from state, which the sensor must persist across restarts:
// restarting from the zero state is reported by the verifier as a replay.
func NewSealer(hostID string, key ed25519.PrivateKey, state ChainState) *Sealer {
	return &Sealer{hostID: hostID, key: key, state: state}
}

// Seal builds and signs the next envelope in the chain.
func (s *Sealer) Seal(kind Kind, payload []byte, now time.Time) Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := Envelope{
		HostID:   s.hostID,
		Sequence: s.state.Sequence + 1,
		PrevHash: s.state.LastDigest,
		SentAt:   now.UTC(),
		Kind:     kind,
		Payload:  payload,
	}
	digest := e.Digest()
	e.Signature = ed25519.Sign(s.key, digest)
	s.state = ChainState{Sequence: e.Sequence, LastDigest: digest}
	return e
}

// Rewind takes the chain back to before e, when e is the last envelope sealed and the verifier
// refused it without recording it: the next envelope takes its sequence number. It reports
// whether it did.
func (s *Sealer) Rewind(e Envelope) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Sequence == 0 || s.state.Sequence != e.Sequence || !bytes.Equal(s.state.LastDigest, e.Digest()) {
		return false
	}
	s.state = ChainState{Sequence: e.Sequence - 1, LastDigest: e.PrevHash}
	return true
}

// State returns the current chain position, to be persisted after each send.
func (s *Sealer) State() ChainState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}
