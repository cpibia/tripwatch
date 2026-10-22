package protocol

import (
	"bytes"
	"crypto/ed25519"
	"errors"
)

var (
	ErrInvalidKey   = errors.New("protocol: invalid public key")
	ErrWrongHost    = errors.New("protocol: envelope from another host")
	ErrUnknownKind  = errors.New("protocol: unknown envelope kind")
	ErrBadSignature = errors.New("protocol: invalid signature")
	ErrReplay       = errors.New("protocol: sequence already accepted")
	ErrSequenceGap  = errors.New("protocol: sequence gap")
	ErrChainBroken  = errors.New("protocol: previous hash does not match the chain")
)

// Verify checks e against the host it is expected from, that host's public key and the last
// accepted chain position. On success it returns the position to persist; on failure it
// returns last unchanged, so a rejected envelope never moves the chain.
func Verify(e Envelope, host string, pub ed25519.PublicKey, last ChainState) (ChainState, error) {
	if len(pub) != ed25519.PublicKeySize {
		return last, ErrInvalidKey
	}
	if e.HostID != host {
		return last, ErrWrongHost
	}
	switch e.Kind {
	case KindHeartbeat, KindEvent, KindSnapshot:
	default:
		return last, ErrUnknownKind
	}

	digest := e.Digest()
	if !ed25519.Verify(pub, digest, e.Signature) {
		return last, ErrBadSignature
	}

	switch {
	case e.Sequence <= last.Sequence:
		return last, ErrReplay
	case e.Sequence > last.Sequence+1:
		return last, ErrSequenceGap
	case !bytes.Equal(e.PrevHash, last.LastDigest):
		return last, ErrChainBroken
	}

	return ChainState{Sequence: e.Sequence, LastDigest: digest}, nil
}
