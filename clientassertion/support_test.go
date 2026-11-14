// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
)

const testAudience = "https://server.example"

// fakeClock is a clock a test moves by hand.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_800_000_000, 0).UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeRegistry is a replay registry double that records every call.
type fakeRegistry struct {
	mu      sync.Mutex
	calls   int
	keys    []string
	expires []time.Time
	seen    map[string]struct{}
	err     error
}

func (r *fakeRegistry) Register(_ context.Context, key string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.keys = append(r.keys, key)
	r.expires = append(r.expires, expiresAt)
	if r.err != nil {
		return r.err
	}
	if r.seen == nil {
		r.seen = map[string]struct{}{}
	}
	if _, duplicate := r.seen[key]; duplicate {
		return replay.ErrDuplicateHandle
	}
	r.seen[key] = struct{}{}
	return nil
}

func (r *fakeRegistry) RemoveExpired(context.Context, time.Time) (int, error) { return 0, nil }

func (r *fakeRegistry) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// syncBuffer is a log sink safe for concurrent writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fixture is a verifier over doubles.
type fixture struct {
	mu       sync.Mutex
	options  Options
	clock    *fakeClock
	registry *fakeRegistry
	keys     *KeySource
	verifier *Verifier
	logs     *syncBuffer
	logger   *slog.Logger
	sequence int
}

func newFixture(options Options) *fixture {
	f := &fixture{options: options, clock: newFakeClock(), registry: &fakeRegistry{}, logs: &syncBuffer{}}
	f.logger = slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	f.keys = NewKeySource(f.currentOptions, f.clock, f.logger)
	f.verifier = NewVerifier(f.currentOptions, f.keys, f.registry, f.clock, f.logger)
	return f
}

func (f *fixture) currentOptions() Options {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.options
}

// claims returns a valid claim set for id with a fresh jti.
func (f *fixture) claims(id string) map[string]any {
	f.mu.Lock()
	f.sequence++
	sequence := f.sequence
	f.mu.Unlock()
	return map[string]any{
		"iss": id,
		"sub": id,
		"aud": testAudience,
		"exp": f.clock.Now().Add(time.Minute).Unix(),
		"jti": fmt.Sprintf("jti-%d", sequence),
	}
}

func (f *fixture) verify(principal Principal, assertion string) error {
	return f.verifier.Verify(context.Background(), principal, testAudience, assertion)
}

// testKey is a signing key generated for the test run.
type testKey struct {
	kid     string
	private crypto.Signer
}

var (
	rsaKeyOnce   sync.Once
	rsaKeyShared *rsa.PrivateKey
)

func sharedRsaKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	rsaKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		rsaKeyShared = key
	})
	return rsaKeyShared
}

func newRsaKey(t testing.TB, kid string) testKey {
	t.Helper()
	return testKey{kid: kid, private: sharedRsaKey(t)}
}

func newFreshRsaKey(t testing.TB, kid string, bits int) testKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return testKey{kid: kid, private: key}
}

func newEcKey(t testing.TB, kid string, curve elliptic.Curve) testKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	return testKey{kid: kid, private: key}
}

// keyFor returns a key that matches algorithm.
func keyFor(t testing.TB, algorithm string, kid string) testKey {
	t.Helper()
	switch algorithm {
	case "ES256":
		return newEcKey(t, kid, elliptic.P256())
	case "ES384":
		return newEcKey(t, kid, elliptic.P384())
	case "ES512":
		return newEcKey(t, kid, elliptic.P521())
	default:
		return newRsaKey(t, kid)
	}
}

func encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

// jwk returns the public JWK of the key.
func (k testKey) jwk(t testing.TB) map[string]any {
	t.Helper()
	member := map[string]any{}
	if k.kid != "" {
		member["kid"] = k.kid
	}
	switch private := k.private.(type) {
	case *rsa.PrivateKey:
		member["kty"] = "RSA"
		member["n"] = encode(private.N.Bytes())
		member["e"] = encode(big.NewInt(int64(private.E)).Bytes())
	case *ecdsa.PrivateKey:
		point, err := private.PublicKey.Bytes()
		if err != nil {
			t.Fatalf("encode ec point: %v", err)
		}
		size := (len(point) - 1) / 2
		member["kty"] = "EC"
		member["crv"] = private.Curve.Params().Name
		member["x"] = encode(point[1 : 1+size])
		member["y"] = encode(point[1+size:])
	default:
		t.Fatalf("unexpected key type %T", k.private)
	}
	return member
}

// keySet renders a JWK Set document of the public keys.
func keySet(t testing.TB, keys ...testKey) string {
	t.Helper()
	members := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		members = append(members, key.jwk(t))
	}
	document, err := json.Marshal(map[string]any{"keys": members})
	if err != nil {
		t.Fatalf("marshal key set: %v", err)
	}
	return string(document)
}

func digestFor(t testing.TB, algorithm string) (crypto.Hash, func() hash.Hash) {
	t.Helper()
	switch algorithm[2:] {
	case "256":
		return crypto.SHA256, sha256.New
	case "384":
		return crypto.SHA384, sha512.New384
	case "512":
		return crypto.SHA512, sha512.New
	}
	t.Fatalf("unexpected algorithm %q", algorithm)
	return 0, nil
}

// sign renders a compact assertion. headerAlgorithm is what the header
// declares; the signature is produced as signAlgorithm would, so a test can
// make the two disagree.
func (k testKey) signAs(t testing.TB, headerAlgorithm string, signAlgorithm string, header map[string]any, claims map[string]any) string {
	t.Helper()
	protected := map[string]any{"alg": headerAlgorithm}
	if k.kid != "" {
		protected["kid"] = k.kid
	}
	for name, value := range header {
		protected[name] = value
	}
	rawHeader, err := json.Marshal(protected)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	rawClaims, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	input := encode(rawHeader) + "." + encode(rawClaims)
	identifier, newHash := digestFor(t, signAlgorithm)
	hasher := newHash()
	hasher.Write([]byte(input))
	digest := hasher.Sum(nil)

	var signature []byte
	switch private := k.private.(type) {
	case *rsa.PrivateKey:
		if signAlgorithm[:2] == "PS" {
			signature, err = rsa.SignPSS(rand.Reader, private, identifier, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			signature, err = rsa.SignPKCS1v15(rand.Reader, private, identifier, digest)
		}
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, private, digest)
		if err == nil {
			size := (private.Curve.Params().BitSize + 7) / 8
			signature = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
		}
	}
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return input + "." + encode(signature)
}

func (k testKey) sign(t testing.TB, algorithm string, claims map[string]any) string {
	t.Helper()
	return k.signAs(t, algorithm, algorithm, nil, claims)
}

// macAssertion renders an assertion authenticated with an HMAC over secret.
func macAssertion(t testing.TB, algorithm string, secret []byte, claims map[string]any) string {
	t.Helper()
	rawHeader, _ := json.Marshal(map[string]any{"alg": algorithm})
	rawClaims, _ := json.Marshal(claims)
	input := encode(rawHeader) + "." + encode(rawClaims)
	_, newHash := digestFor(t, algorithm)
	mac := hmac.New(newHash, secret)
	mac.Write([]byte(input))
	return input + "." + encode(mac.Sum(nil))
}

// unsignedAssertion renders an assertion with the given alg and signature.
func unsignedAssertion(algorithm string, signature string, claims map[string]any) string {
	rawHeader, _ := json.Marshal(map[string]any{"alg": algorithm})
	rawClaims, _ := json.Marshal(claims)
	return encode(rawHeader) + "." + encode(rawClaims) + "." + signature
}

func mustJson(t testing.TB, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
