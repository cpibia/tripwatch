package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Headers of the verifier's answer that carry an update order and its signature.
const (
	UpdateHeader          = "Tripwatch-Update"
	UpdateSignatureHeader = "Tripwatch-Update-Signature"
)

const updateDomain = "tripwatch/update/v1\n"

// Bounds of an update order: it reaches every sensor as root, so it is parsed only when small.
const (
	maxUpdateOrderSize = 8 << 10
	maxUpdateSums      = 32
)

var (
	updateVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	updateAsset   = regexp.MustCompile(`^tripwatch-sensor[A-Za-z0-9._-]{1,120}$`)
	sha256Hex     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// UpdateOrder tells sensors to install a release, with the hash of each of its files: the
// verifier signs it with its CA key, which every sensor holds since enrollment, so a release
// changed where it is published, or an order from anyone else, installs nothing.
type UpdateOrder struct {
	Version  string            `json:"version"`
	Sums     map[string]string `json:"sums"`
	IssuedAt time.Time         `json:"issued_at"`
}

// SignUpdate encodes order and signs it, returning both as header values.
func SignUpdate(order UpdateOrder, key ed25519.PrivateKey) (payload, signature string, err error) {
	if err := order.check(); err != nil {
		return "", "", err
	}
	data, err := json.Marshal(order)
	if err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(key, append([]byte(updateDomain), data...))
	return base64.RawURLEncoding.EncodeToString(data), base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyUpdate checks the signature of an order received as header values and decodes it.
func VerifyUpdate(payload, signature string, pub ed25519.PublicKey) (UpdateOrder, error) {
	var order UpdateOrder
	if len(payload) > maxUpdateOrderSize*4/3+4 || len(signature) > 128 {
		return order, errors.New("update order too large")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return order, fmt.Errorf("update order: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return order, fmt.Errorf("update signature: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, append([]byte(updateDomain), data...), sig) {
		return order, errors.New("update order: bad signature")
	}
	if err := json.Unmarshal(data, &order); err != nil {
		return order, fmt.Errorf("update order: %w", err)
	}
	return order, order.check()
}

func (o UpdateOrder) check() error {
	if !updateVersion.MatchString(o.Version) {
		return fmt.Errorf("update order: %q is not a release version", o.Version)
	}
	if len(o.Sums) == 0 || len(o.Sums) > maxUpdateSums {
		return fmt.Errorf("update order: %d file hashes", len(o.Sums))
	}
	for name, sum := range o.Sums {
		if !updateAsset.MatchString(name) || strings.Contains(name, "..") || !sha256Hex.MatchString(sum) {
			return fmt.Errorf("update order: bad entry %q", name)
		}
	}
	return nil
}

// Headers of the verifier's answer to a revoked host that carry its uninstall order.
const (
	UninstallHeader          = "Tripwatch-Uninstall"
	UninstallSignatureHeader = "Tripwatch-Uninstall-Signature"
)

const uninstallDomain = "tripwatch/uninstall/v1\n"

// UninstallOrder tells the sensor of one host, named in it, to remove itself and its data: the
// verifier gives it to a host it revoked, signed with its CA key.
type UninstallOrder struct {
	HostID   string    `json:"host_id"`
	IssuedAt time.Time `json:"issued_at"`
}

// SignUninstall encodes order and signs it, returning both as header values.
func SignUninstall(order UninstallOrder, key ed25519.PrivateKey) (payload, signature string, err error) {
	data, err := json.Marshal(order)
	if err != nil {
		return "", "", err
	}
	sig := ed25519.Sign(key, append([]byte(uninstallDomain), data...))
	return base64.RawURLEncoding.EncodeToString(data), base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyUninstall checks an uninstall order received as header values and that it names host.
func VerifyUninstall(payload, signature string, pub ed25519.PublicKey, host string) (UninstallOrder, error) {
	var order UninstallOrder
	if len(payload) > 1024 || len(signature) > 128 {
		return order, errors.New("uninstall order too large")
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return order, fmt.Errorf("uninstall order: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return order, fmt.Errorf("uninstall signature: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, append([]byte(uninstallDomain), data...), sig) {
		return order, errors.New("uninstall order: bad signature")
	}
	if err := json.Unmarshal(data, &order); err != nil {
		return order, fmt.Errorf("uninstall order: %w", err)
	}
	if order.HostID != host {
		return order, fmt.Errorf("uninstall order for %q, not this host", order.HostID)
	}
	return order, nil
}
