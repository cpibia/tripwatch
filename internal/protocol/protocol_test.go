package protocol

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

var testTime = time.Date(2026, 10, 22, 18, 47, 0, 123456789, time.UTC)

func newTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestChainAcceptsConsecutiveEnvelopes(t *testing.T) {
	pub, priv := newTestKey(t)
	sealer := NewSealer("web-01", priv, ChainState{})

	var state ChainState
	for i := range 3 {
		e := sealer.Seal(KindHeartbeat, nil, testTime.Add(time.Duration(i)*time.Minute))
		var err error
		if state, err = Verify(e, pub, state); err != nil {
			t.Fatalf("envelope %d rejected: %v", e.Sequence, err)
		}
	}

	if state.Sequence != 3 {
		t.Fatalf("sequence = %d, want 3", state.Sequence)
	}
	if got := sealer.State(); got.Sequence != state.Sequence || string(got.LastDigest) != string(state.LastDigest) {
		t.Fatal("sealer and verifier disagree on the chain position")
	}
}

// Payloads carry raw file content such as PHP, which encoding/json would escape if it were
// embedded JSON; the signature must survive the trip over the wire.
func TestSignatureSurvivesJSONRoundTrip(t *testing.T) {
	pub, priv := newTestKey(t)
	e := NewSealer("web-01", priv, ChainState{}).Seal(KindEvent, []byte(`{"line":"<?php system($_POST['cmd']); ?>"}`), testTime)

	wire, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var received Envelope
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatal(err)
	}

	if _, err := Verify(received, pub, ChainState{}); err != nil {
		t.Fatalf("round-tripped envelope rejected: %v", err)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := newTestKey(t)
	otherPub, otherPriv := newTestKey(t)

	sealer := NewSealer("web-01", priv, ChainState{})
	first := sealer.Seal(KindHeartbeat, nil, testTime)
	afterFirst := sealer.State()
	second := sealer.Seal(KindHeartbeat, nil, testTime.Add(time.Minute))
	third := sealer.Seal(KindHeartbeat, nil, testTime.Add(2*time.Minute))

	tampered := second
	tampered.Payload = []byte("forged")

	// Correctly signed and numbered, but built on a chain the verifier never saw.
	forkedState := ChainState{Sequence: 1, LastDigest: []byte("not the real digest")}
	forked := NewSealer("web-01", priv, forkedState).Seal(KindHeartbeat, nil, testTime)

	tests := []struct {
		name  string
		e     Envelope
		pub   ed25519.PublicKey
		state ChainState
		want  error
	}{
		{"malformed key", second, ed25519.PublicKey("short"), afterFirst, ErrInvalidKey},
		{"tampered payload", tampered, pub, afterFirst, ErrBadSignature},
		{"signed by another key", NewSealer("web-01", otherPriv, ChainState{}).Seal(KindHeartbeat, nil, testTime), pub, ChainState{}, ErrBadSignature},
		{"wrong key for host", first, otherPub, ChainState{}, ErrBadSignature},
		{"replay", first, pub, afterFirst, ErrReplay},
		{"restart from zero state", NewSealer("web-01", priv, ChainState{}).Seal(KindHeartbeat, nil, testTime), pub, afterFirst, ErrReplay},
		{"dropped envelope", third, pub, afterFirst, ErrSequenceGap},
		{"forked chain", forked, pub, afterFirst, ErrChainBroken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.e, tt.pub, tt.state)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if got.Sequence != tt.state.Sequence || string(got.LastDigest) != string(tt.state.LastDigest) {
				t.Fatal("rejected envelope moved the chain")
			}
		})
	}
}

func TestDigestBindsEveryField(t *testing.T) {
	base := Envelope{HostID: "web-01", Sequence: 7, PrevHash: []byte("prev"), SentAt: testTime, Kind: KindEvent, Payload: []byte("data")}
	baseDigest := string(base.Digest())

	mutations := map[string]func(*Envelope){
		"host":     func(e *Envelope) { e.HostID = "web-02" },
		"sequence": func(e *Envelope) { e.Sequence = 8 },
		"prev":     func(e *Envelope) { e.PrevHash = []byte("other") },
		"time":     func(e *Envelope) { e.SentAt = e.SentAt.Add(time.Nanosecond) },
		"kind":     func(e *Envelope) { e.Kind = KindSnapshot },
		"payload":  func(e *Envelope) { e.Payload = []byte("dat") },
		"boundary": func(e *Envelope) { e.HostID, e.Kind = "web-01e", "vent" },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := base
			mutate(&e)
			if string(e.Digest()) == baseDigest {
				t.Fatal("digest did not change")
			}
		})
	}
}
