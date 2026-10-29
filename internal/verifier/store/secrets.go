package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// sealedPrefix marks a channel's settings sealed with the secrets key; settings without it are
// the plain JSON of verifiers before it, sealed when the key is set.
const sealedPrefix = "sealed:v1:"

// SecretsKeySize is the length of the key that seals the channels' settings: AES-256.
const SecretsKeySize = 32

// ErrSealed is returned for settings sealed with another key than the one set.
var ErrSealed = errors.New("store: the channel's settings were sealed with another key")

// SetSecretsKey seals the channels' settings, which hold passwords, bot tokens and webhook
// secrets, with key from now on, and seals those still kept in plain text. A copy of the
// database alone, a backup handed around or a file read through a bug, then holds none of them.
func (s *Store) SetSecretsKey(ctx context.Context, key []byte) error {
	if len(key) != SecretsKeySize {
		return errors.New("store: the secrets key is 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	if s.sealer, err = cipher.NewGCM(block); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, settings FROM channels WHERE settings NOT LIKE ?`, sealedPrefix+"%")
	if err != nil {
		return err
	}
	plain := map[int64]string{}
	for rows.Next() {
		var id int64
		var settings string
		if err := rows.Scan(&id, &settings); err != nil {
			_ = rows.Close()
			return err
		}
		plain[id] = settings
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for id, settings := range plain {
		sealed, err := s.seal(settings)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE channels SET settings = ? WHERE id = ?`, sealed, id); err != nil {
			return err
		}
	}
	return nil
}

// seal returns settings sealed with the key, or as they are when no key is set.
func (s *Store) seal(settings string) (string, error) {
	if s.sealer == nil {
		return settings, nil
	}
	nonce := make([]byte, s.sealer.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return sealedPrefix + base64.StdEncoding.EncodeToString(s.sealer.Seal(nonce, nonce, []byte(settings), []byte("channel"))), nil
}

// unseal returns the plain settings.
func (s *Store) unseal(stored string) (string, error) {
	raw, sealed := strings.CutPrefix(stored, sealedPrefix)
	if !sealed {
		return stored, nil
	}
	if s.sealer == nil {
		return "", ErrSealed
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(data) < s.sealer.NonceSize() {
		return "", ErrSealed
	}
	plain, err := s.sealer.Open(nil, data[:s.sealer.NonceSize()], data[s.sealer.NonceSize():], []byte("channel"))
	if err != nil {
		return "", ErrSealed
	}
	return string(plain), nil
}
