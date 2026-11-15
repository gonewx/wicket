// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Server nonces (RFC 9449 section 8) are stateless: a nonce carries the
// instant it was issued and the identifier of the key that authenticated
// it, and is checked by recomputing its MAC. Nothing is stored. Every
// replica that is given the same key source accepts the nonces of the
// others.
//
// A nonce is the unpadded base64url encoding of
//
//	0x01 | issuedAt (int64, big endian, Unix seconds) | len(id) (1 byte) | id | mac (32 bytes)
//
// where mac is HMAC-SHA256 under the key secret over
//
//	"wicket dpop nonce v1" 0x00 | uint32 big endian len(surface) | surface | 0x01 | issuedAt | len(id) | id
//
// The surface names the issuing side, so a nonce issued for one surface is
// refused by another that shares the keys.
const (
	// nonceVersion is the first byte of every nonce.
	nonceVersion byte = 0x01
	// noncePurpose separates the MAC of a nonce from any other use of the
	// key.
	noncePurpose = "wicket dpop nonce v1"
	// minNonceSecretBytes is the least accepted key secret length.
	minNonceSecretBytes = 32
	// maxNonceKeyIdBytes bounds the length of a key identifier.
	maxNonceKeyIdBytes = 32
	// maxNonceEncodedLength bounds the length of a presented nonce; the
	// longest nonce issued is 99 characters.
	maxNonceEncodedLength = 128
	// nonceMacBytes is the length of the MAC.
	nonceMacBytes = sha256.Size
	// nonceFixedBytes is the length of a nonce without its key identifier.
	nonceFixedBytes = 1 + 8 + 1 + nonceMacBytes
)

// ErrInvalidNonce reports a presented nonce that is malformed, was not
// issued with a known key for the surface, or is outside its time window.
// Any other error of NonceSealer means the nonce could not be judged.
var ErrInvalidNonce = errors.New("dpop: invalid nonce")

// NonceKey is one key that authenticates server nonces.
type NonceKey struct {
	// Id names the key inside each nonce: 1 to 32 bytes of A-Z, a-z, 0-9,
	// '.', '_' and '-'. It is not secret.
	Id string
	// Secret is the HMAC-SHA256 key, at least 32 bytes.
	Secret []byte
}

// NonceKeySource provides the keys of server nonces. It is read on every
// issue and every check, so an implementation may rotate keys while
// running. Every replica has to be given the same keys.
type NonceKeySource interface {
	// NonceKeys returns the key new nonces are issued with and the keys
	// that are still accepted for nonces issued earlier. An error means
	// the keys are unavailable.
	NonceKeys() (current NonceKey, previous []NonceKey, err error)
}

// ValidateNonceKeys rejects keys that cannot be served: a secret shorter
// than 32 bytes, an empty identifier, one longer than 32 bytes or holding a
// character outside A-Z, a-z, 0-9, '.', '_' and '-', and an identifier used
// twice.
func ValidateNonceKeys(current NonceKey, previous []NonceKey) error {
	seen := make(map[string]struct{}, 1+len(previous))
	for index, key := range append([]NonceKey{current}, previous...) {
		position := "current"
		if index > 0 {
			position = fmt.Sprintf("previous[%d]", index-1)
		}
		if err := validateNonceKey(key); err != nil {
			return fmt.Errorf("%s nonce key: %w", position, err)
		}
		if _, duplicate := seen[key.Id]; duplicate {
			return fmt.Errorf("%s nonce key: id %q used more than once", position, key.Id)
		}
		seen[key.Id] = struct{}{}
	}
	return nil
}

func validateNonceKey(key NonceKey) error {
	if len(key.Id) == 0 || len(key.Id) > maxNonceKeyIdBytes {
		return fmt.Errorf("id must be 1 to %d bytes", maxNonceKeyIdBytes)
	}
	for _, c := range []byte(key.Id) {
		if !nonceKeyIdByte(c) {
			return errors.New("id holds a character outside A-Z, a-z, 0-9, '.', '_' and '-'")
		}
	}
	if len(key.Secret) < minNonceSecretBytes {
		return fmt.Errorf("secret must be at least %d bytes", minNonceSecretBytes)
	}
	return nil
}

func nonceKeyIdByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// staticNonceKeys is a fixed key set.
type staticNonceKeys struct {
	current  NonceKey
	previous []NonceKey
}

// NewStaticNonceKeys returns a source that always provides current and
// previous. The keys are copied. It fails for keys ValidateNonceKeys
// rejects.
func NewStaticNonceKeys(current NonceKey, previous ...NonceKey) (NonceKeySource, error) {
	if err := ValidateNonceKeys(current, previous); err != nil {
		return nil, err
	}
	source := &staticNonceKeys{current: cloneNonceKey(current)}
	for _, key := range previous {
		source.previous = append(source.previous, cloneNonceKey(key))
	}
	return source, nil
}

func (s *staticNonceKeys) NonceKeys() (NonceKey, []NonceKey, error) {
	previous := make([]NonceKey, 0, len(s.previous))
	for _, key := range s.previous {
		previous = append(previous, cloneNonceKey(key))
	}
	return cloneNonceKey(s.current), previous, nil
}

func cloneNonceKey(key NonceKey) NonceKey {
	return NonceKey{Id: key.Id, Secret: slices.Clone(key.Secret)}
}

// NonceSealer issues and checks server nonces with the keys of a source.
type NonceSealer struct {
	source   NonceKeySource
	lifetime time.Duration
	skew     time.Duration
}

// NewNonceSealer returns a sealer over source that applies the nonce
// lifetime and clock skew of options; zero fields take their defaults. A nil
// source fails every issue and check.
func NewNonceSealer(source NonceKeySource, options Options) *NonceSealer {
	options = options.withDefaults()
	return &NonceSealer{source: source, lifetime: options.NonceLifetime, skew: options.ClockSkew}
}

// keys reads and validates the keys of the source.
func (s *NonceSealer) keys() (NonceKey, []NonceKey, error) {
	if s == nil || s.source == nil {
		return NonceKey{}, nil, errors.New("dpop: no nonce key source")
	}
	current, previous, err := s.source.NonceKeys()
	if err != nil {
		return NonceKey{}, nil, fmt.Errorf("dpop: nonce keys unavailable: %w", err)
	}
	if err := ValidateNonceKeys(current, previous); err != nil {
		return NonceKey{}, nil, fmt.Errorf("dpop: nonce key source returned invalid keys: %w", err)
	}
	return current, previous, nil
}

// Issue returns a new nonce for surface, issued at now with the current
// key. It fails when the keys are unavailable or invalid, or surface is
// empty.
func (s *NonceSealer) Issue(surface string, now time.Time) (string, error) {
	if surface == "" {
		return "", errors.New("dpop: empty nonce surface")
	}
	current, _, err := s.keys()
	if err != nil {
		return "", err
	}
	body := nonceBody(now.Unix(), current.Id)
	sealed := append(body, nonceMac(current.Secret, surface, body)...)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Check judges a presented nonce for surface at now. A nonce is accepted
// when it was issued for surface with the current or a previous key, no
// later than now plus the clock skew, and now is no later than its issue
// instant plus the nonce lifetime plus the clock skew. It returns the
// deadline of the nonce: its issue instant plus the nonce lifetime. A
// refused nonce yields an error matching ErrInvalidNonce; any other error
// means the keys are unavailable or invalid and nothing may be concluded.
func (s *NonceSealer) Check(nonce string, surface string, now time.Time) (time.Time, error) {
	if len(nonce) == 0 || len(nonce) > maxNonceEncodedLength {
		return time.Time{}, invalidNonce("size")
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil {
		return time.Time{}, invalidNonce("encoding")
	}
	if len(sealed) < nonceFixedBytes+1 || sealed[0] != nonceVersion {
		return time.Time{}, invalidNonce("format")
	}
	idLength := int(sealed[9])
	if idLength == 0 || idLength > maxNonceKeyIdBytes || len(sealed) != nonceFixedBytes+idLength {
		return time.Time{}, invalidNonce("format")
	}
	if surface == "" {
		return time.Time{}, errors.New("dpop: empty nonce surface")
	}
	body := sealed[:len(sealed)-nonceMacBytes]
	mac := sealed[len(sealed)-nonceMacBytes:]
	id := string(body[10:])

	current, previous, err := s.keys()
	if err != nil {
		return time.Time{}, err
	}
	var secret []byte
	for _, key := range append([]NonceKey{current}, previous...) {
		if key.Id == id {
			secret = key.Secret
			break
		}
	}
	if secret == nil {
		return time.Time{}, invalidNonce("unknown key")
	}
	if !hmac.Equal(mac, nonceMac(secret, surface, body)) {
		return time.Time{}, invalidNonce("mac")
	}

	issuedAt := time.Unix(int64(binary.BigEndian.Uint64(body[1:9])), 0)
	if issuedAt.After(now.Add(s.skew)) {
		return time.Time{}, invalidNonce("issued in the future")
	}
	deadline := issuedAt.Add(s.lifetime)
	if now.After(deadline.Add(s.skew)) {
		return time.Time{}, invalidNonce("expired")
	}
	return deadline, nil
}

// nonceBody is the part of a nonce the MAC follows.
func nonceBody(issuedAt int64, id string) []byte {
	body := make([]byte, 0, nonceFixedBytes+len(id))
	body = append(body, nonceVersion)
	body = binary.BigEndian.AppendUint64(body, uint64(issuedAt))
	body = append(body, byte(len(id)))
	return append(body, id...)
}

// nonceMac authenticates body for surface under secret.
func nonceMac(secret []byte, surface string, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(noncePurpose))
	mac.Write([]byte{0x00})
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(surface))))
	mac.Write([]byte(surface))
	mac.Write(body)
	return mac.Sum(nil)
}

func invalidNonce(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNonce, reason)
}
