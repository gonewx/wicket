// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dpop"
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const nonceTestSurface = "authorization-server https://wicket.test"

var nonceTestNow = time.Unix(1_800_000_000, 0)

// nonceProofSequence numbers the proof identifiers of these tests.
var nonceProofSequence atomic.Int64

// countingClientValidator counts the client authentications it was asked
// for.
type countingClientValidator struct{ calls atomic.Int64 }

func (v *countingClientValidator) Validate(*http.Request) *validators_models.ClientSecretValidationResult {
	v.calls.Add(1)
	return successClientResult()
}

// countingProofRegistry counts registrations and keeps the last expiry.
type countingProofRegistry struct {
	calls     atomic.Int64
	expiresAt time.Time
}

func (r *countingProofRegistry) Register(_ context.Context, _ string, expiresAt time.Time) error {
	r.calls.Add(1)
	r.expiresAt = expiresAt
	return nil
}

func (*countingProofRegistry) RemoveExpired(context.Context, time.Time) (int, error) { return 0, nil }

type failingNonceSource struct{ marker string }

func (s failingNonceSource) NonceKeys() (dpop.NonceKey, []dpop.NonceKey, error) {
	return dpop.NonceKey{}, nil, errors.New(s.marker)
}

func nonceTestKeys(t *testing.T) dpop.NonceKeySource {
	t.Helper()
	source, err := dpop.NewStaticNonceKeys(dpop.NonceKey{Id: "k1", Secret: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// nonceProof signs a proof for the test token endpoint, with nonce when it
// is not empty.
func nonceProof(t *testing.T, key *ecdsa.PrivateKey, nonce string) string {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	x, y := make([]byte, 32), make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	header, _ := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256",
		"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": encode(x), "y": encode(y)},
	})
	claims := map[string]any{
		"jti": "jti-" + strconv.FormatInt(nonceProofSequence.Add(1), 10),
		"htm": http.MethodPost, "htu": "https://wicket.test" + wicket.ProtocolRoutePathsToken, "iat": nonceTestNow.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, _ := json.Marshal(claims)
	input := encode(header) + "." + encode(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + encode(signature)
}

type nonceHandler struct {
	handler  *TokenHandler
	clients  *countingClientValidator
	registry *countingProofRegistry
	logs     *bytes.Buffer
}

func newNonceHandler(t *testing.T, source dpop.NonceKeySource) nonceHandler {
	t.Helper()
	logs := &bytes.Buffer{}
	h := nonceHandler{clients: &countingClientValidator{}, registry: &countingProofRegistry{}, logs: logs}
	h.handler = NewTokenHandler(
		h.clients,
		&fakeTokenRequestValidator{result: validators_models.NewTokenRequestValidationResult(validators_models.NewValidatedTokenRequest())},
		&fakeTokenResponseGenerator{response: &responses_models.TokenResponse{AccessToken: "at"}},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
	options := dpop.Options{RequireNonce: true, ProofLifetime: time.Minute, ClockSkew: 10 * time.Second, NonceLifetime: 5 * time.Minute}
	h.handler.SetDPoP(dpop.NewVerifier(options), h.registry, options, fixedClock{now: nonceTestNow})
	h.handler.SetDPoPNonces(dpop.NewNonceSealer(source, options))
	h.handler.dpop.surface = func(*http.Request) (string, bool) { return nonceTestSurface, true }
	return h
}

func (h nonceHandler) post(t *testing.T, proofs ...string) *httptest.ResponseRecorder {
	t.Helper()
	request := newTokenForm()
	for _, proof := range proofs {
		request.Header.Add(wicket.DPoPHeaderName, proof)
	}
	recorder := httptest.NewRecorder()
	if err := h.handler.Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}
	return recorder
}

func tokenError(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", recorder.Body.String(), err)
	}
	value, _ := body["error"].(string)
	return value
}

func TestTokenHandlerNonceChallengePrecedesClientAuthentication(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := newNonceHandler(t, nonceTestKeys(t))

	challenge := h.post(t, nonceProof(t, key, ""))
	if challenge.Code != http.StatusBadRequest || tokenError(t, challenge) != "use_dpop_nonce" {
		t.Fatalf("status %d body %s", challenge.Code, challenge.Body.String())
	}
	nonce := challenge.Header().Get(wicket.DPoPNonceHeaderName)
	if nonce == "" {
		t.Fatal("challenge carries no nonce")
	}
	if h.clients.calls.Load() != 0 || h.registry.calls.Load() != 0 {
		t.Fatalf("challenge authenticated the client %d times and registered %d proofs", h.clients.calls.Load(), h.registry.calls.Load())
	}

	replacement := "A"
	if nonce[20] == 'A' {
		replacement = "B"
	}
	forged := h.post(t, nonceProof(t, key, nonce[:20]+replacement+nonce[21:]))
	if forged.Code != http.StatusBadRequest || tokenError(t, forged) != "use_dpop_nonce" || forged.Header().Get(wicket.DPoPNonceHeaderName) == "" {
		t.Fatalf("forged nonce: status %d body %s", forged.Code, forged.Body.String())
	}
	if h.clients.calls.Load() != 0 || h.registry.calls.Load() != 0 {
		t.Fatal("refused nonce reached client authentication")
	}

	accepted := h.post(t, nonceProof(t, key, nonce))
	if accepted.Code != http.StatusOK {
		t.Fatalf("retry: status %d body %s", accepted.Code, accepted.Body.String())
	}
	if accepted.Header().Get(wicket.DPoPNonceHeaderName) == "" {
		t.Fatal("success carries no nonce")
	}
	if h.clients.calls.Load() != 1 || h.registry.calls.Load() != 1 {
		t.Fatalf("client authentications %d, registrations %d", h.clients.calls.Load(), h.registry.calls.Load())
	}
	// The registration lasts until the nonce deadline plus the clock skew.
	if want := nonceTestNow.Add(5*time.Minute + 10*time.Second); !h.registry.expiresAt.Equal(want) {
		t.Fatalf("registration expires %s, want %s", h.registry.expiresAt, want)
	}
}

func TestTokenHandlerNonceHeaderOnlyForDPoPRequests(t *testing.T) {
	t.Parallel()
	h := newNonceHandler(t, nonceTestKeys(t))

	invalid := h.post(t, "not.a.proof")
	if invalid.Code != http.StatusBadRequest || tokenError(t, invalid) != "invalid_dpop_proof" {
		t.Fatalf("status %d body %s", invalid.Code, invalid.Body.String())
	}
	if invalid.Header().Get(wicket.DPoPNonceHeaderName) == "" {
		t.Fatal("invalid proof answered without a nonce")
	}

	plain := h.post(t)
	if plain.Code != http.StatusOK || plain.Header().Get(wicket.DPoPNonceHeaderName) != "" {
		t.Fatalf("request without DPoP: status %d nonce %q", plain.Code, plain.Header().Get(wicket.DPoPNonceHeaderName))
	}
}

func TestTokenHandlerNonceUnavailableIsAServerError(t *testing.T) {
	t.Parallel()
	const marker = "nonce-source-secret-marker"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("key source fails", func(t *testing.T) {
		t.Parallel()
		h := newNonceHandler(t, failingNonceSource{marker: marker})
		r := h.post(t, nonceProof(t, key, ""))
		if r.Code != http.StatusInternalServerError || r.Body.String() != "Internal Server Error\n" {
			t.Fatalf("status %d body %q", r.Code, r.Body.String())
		}
		if r.Header().Get(wicket.DPoPNonceHeaderName) != "" || h.clients.calls.Load() != 0 {
			t.Fatal("nonce sent or client authenticated")
		}
		if !strings.Contains(h.logs.String(), "error_type=") || strings.Contains(h.logs.String(), marker) {
			t.Fatalf("log output %q", h.logs.String())
		}
	})
	t.Run("issuer unavailable", func(t *testing.T) {
		t.Parallel()
		h := newNonceHandler(t, nonceTestKeys(t))
		// Without a request scope the issuer cannot be determined.
		h.handler.dpop.surface = authorizationServerNonceSurface
		r := h.post(t, nonceProof(t, key, ""))
		if r.Code != http.StatusInternalServerError || h.clients.calls.Load() != 0 {
			t.Fatalf("status %d, client authentications %d", r.Code, h.clients.calls.Load())
		}
	})
}

func TestSetDPoPNoncesRequiresSetDPoP(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	NewTokenHandler(nil, nil, nil, nil).SetDPoPNonces(dpop.NewNonceSealer(nil, dpop.Options{}))
}

// failingAfterFirstRead provides valid keys on its first read and fails
// every later read.
type failingAfterFirstRead struct {
	keys  dpop.NonceKeySource
	reads atomic.Int64
}

func (s *failingAfterFirstRead) NonceKeys() (dpop.NonceKey, []dpop.NonceKey, error) {
	if s.reads.Add(1) == 1 {
		return s.keys.NonceKeys()
	}
	return dpop.NonceKey{}, nil, errors.New("nonce source down")
}

func TestTokenHandlerNonceCheckUnavailableIsAServerError(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	options := dpop.Options{RequireNonce: true, ClockSkew: 10 * time.Second}
	nonce, err := dpop.NewNonceSealer(nonceTestKeys(t), options).Issue(nonceTestSurface, nonceTestNow)
	if err != nil {
		t.Fatal(err)
	}
	// The handler's Issue takes the one good read; its Check then fails.
	h := newNonceHandler(t, &failingAfterFirstRead{keys: nonceTestKeys(t)})
	r := h.post(t, nonceProof(t, key, nonce))
	if r.Code != http.StatusInternalServerError || r.Body.String() != "Internal Server Error\n" {
		t.Fatalf("status %d body %q", r.Code, r.Body.String())
	}
	if got := r.Header().Get(wicket.DPoPNonceHeaderName); got != "" {
		t.Fatalf("DPoP-Nonce %q on a server error", got)
	}
	if h.clients.calls.Load() != 0 || h.registry.calls.Load() != 0 {
		t.Fatalf("client authentications %d, registrations %d", h.clients.calls.Load(), h.registry.calls.Load())
	}
}
