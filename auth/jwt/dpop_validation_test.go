// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt_test

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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/jwt"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/replay"
)

// The DPoP contract of the JWT bearer handler is observed on the wire: each
// scene serves a protected endpoint through core.Middleware on an
// httptest.Server, and the endpoint challenges the JWT scheme whenever the
// request did not authenticate, so the status, WWW-Authenticate, DPoP-Nonce
// and Cache-Control headers a client receives are what is asserted.

// dpopTestNow is the fixed instant every scene starts at, a whole second so
// server nonces (Unix seconds) carry it exactly.
var dpopTestNow = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

const (
	dpopResourcePath = "/api/resource"
	dpopAlgs         = `algs="ES256"`
)

// movableClock is a clock a test can move between requests.
type movableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *movableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *movableClock) set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// recordingRegistry records every registration it is offered and delegates
// to an in-memory registry, or fails once fail was called.
type recordingRegistry struct {
	inner   *replay.MemoryRegistry
	mu      sync.Mutex
	keys    []string
	expiry  []time.Time
	failing bool
}

func newRecordingRegistry() *recordingRegistry {
	return &recordingRegistry{inner: replay.NewMemoryRegistry()}
}

// registryDown is the infrastructure failure a failing registry reports. Its
// text carries the key, which must never reach a log.
type registryDown struct{ key string }

func (e registryDown) Error() string { return "registry down while registering " + e.key }

func (r *recordingRegistry) Register(ctx context.Context, key string, expiresAt time.Time) error {
	r.mu.Lock()
	r.keys = append(r.keys, key)
	r.expiry = append(r.expiry, expiresAt)
	failing := r.failing
	r.mu.Unlock()
	if failing {
		return registryDown{key: key}
	}
	return r.inner.Register(ctx, key, expiresAt)
}

func (r *recordingRegistry) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	return r.inner.RemoveExpired(ctx, cutoff)
}

func (r *recordingRegistry) fail() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failing = true
}

func (r *recordingRegistry) registrations() ([]string, []time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.keys...), append([]time.Time(nil), r.expiry...)
}

// count is how many registrations were offered.
func (r *recordingRegistry) count() int {
	keys, _ := r.registrations()
	return len(keys)
}

// lockedBuffer is a log sink safe for the concurrent server goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// switchableNonceKeys is a nonce key source that can be made to fail after
// construction.
type switchableNonceKeys struct {
	source  dpop.NonceKeySource
	failing atomic.Bool
}

func (s *switchableNonceKeys) NonceKeys() (dpop.NonceKey, []dpop.NonceKey, error) {
	if s.failing.Load() {
		return dpop.NonceKey{}, nil, errors.New("key vault unreachable")
	}
	return s.source.NonceKeys()
}

// proofSigner is a P-256 proof key.
type proofSigner struct {
	private    *ecdsa.PrivateKey
	thumbprint string
}

func newProofSigner(t *testing.T) proofSigner {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := jwk.Import(&private.PublicKey)
	require.NoError(t, err)
	thumbprint, err := dpop.Thumbprint(public)
	require.NoError(t, err)
	return proofSigner{private: private, thumbprint: thumbprint}
}

func (s proofSigner) publicJwk() map[string]any {
	encode := func(v []byte) string {
		padded := make([]byte, 32)
		copy(padded[32-len(v):], v)
		return base64.RawURLEncoding.EncodeToString(padded)
	}
	return map[string]any{"kty": "EC", "crv": "P-256", "x": encode(s.private.X.Bytes()), "y": encode(s.private.Y.Bytes())}
}

// sign returns a compact ES256 proof over claims.
func (s proofSigner) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": s.publicJwk()})
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, sig, err := ecdsa.Sign(rand.Reader, s.private, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	sig.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// dpopScene is one protected resource served with DPoP validation.
type dpopScene struct {
	server     *httptest.Server
	clock      *movableClock
	registry   *recordingRegistry
	logs       *lockedBuffer
	tokenKey   jwk.Key
	proofKey   proofSigner
	nonceKeys  *switchableNonceKeys
	options    dpop.Options
	proofCount atomic.Int64
}

type sceneConfig struct {
	requireNonce bool
	// validation, when set, replaces the constructed DPoP validation.
	validation func(*dpopScene) *jwt.DPoPValidation
	// configure adjusts the handler options after DPoP is set.
	configure func(*jwt.Options)
	// off leaves Options.DPoP unset.
	off bool
	// alwaysChallenge makes the endpoint challenge even an authenticated
	// request.
	alwaysChallenge bool
}

func newDPoPScene(t *testing.T, config sceneConfig) *dpopScene {
	t.Helper()
	s := &dpopScene{
		clock:    &movableClock{now: dpopTestNow},
		registry: newRecordingRegistry(),
		logs:     &lockedBuffer{},
		tokenKey: newSigningKey(t, strings.Repeat("d", 128), testKid),
		proofKey: newProofSigner(t),
		options:  dpop.Options{SigningAlgorithms: []string{"ES256"}, RequireNonce: config.requireNonce},
	}
	staticKeys, err := dpop.NewStaticNonceKeys(dpop.NonceKey{Id: "k1", Secret: bytes.Repeat([]byte{7}, 32)})
	require.NoError(t, err)
	s.nonceKeys = &switchableNonceKeys{source: staticKeys}

	opts := newTestOptions(t, keySet(t, s.tokenKey), nil)
	if !config.off {
		if config.validation != nil {
			opts.DPoP = config.validation(s)
		} else {
			validation, err := jwt.NewDPoPValidation(jwt.DPoPValidationConfig{
				Options:   s.options,
				Registry:  s.registry,
				NonceKeys: s.nonceKeys,
				Resource:  "https://api.example",
			})
			require.NoError(t, err)
			opts.DPoP = validation
		}
	}
	if config.configure != nil {
		config.configure(opts)
	}

	logger := slog.New(slog.NewTextHandler(s.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	monitor := staticOptionsMonitor{opts: opts}
	authOptions := auth.NewOptions()
	authOptions.DefaultAuthenticateScheme = jwt.AuthenticationScheme
	schemes := core.NewSchemeProvider(authOptions)
	require.NoError(t, schemes.AddScheme(auth.NewScheme(jwt.AuthenticationScheme, "handler")))

	endpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := core.ResultFromContext(r.Context())
		if !config.alwaysChallenge && result != nil && result.Succeeded() && result.Principal.FindFirst(claims.NameIdentifier) != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		handlers, _ := hosting.ScopeFrom(r.Context()).GetService(reflect.TypeFor[auth.HandlerProvider]()).(auth.HandlerProvider)
		if err := core.NewService(schemes, handlers).Challenge(r, w, jwt.AuthenticationScheme, nil); err != nil {
			t.Errorf("Challenge: %v", err)
		}
	})
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider := newKeyedProvider()
		provider.factories[jwt.AuthenticationScheme] = func() auth.Handler {
			return jwt.NewHandler(monitor, logger, s.clock)
		}
		provider.services[reflect.TypeFor[auth.HandlerProvider]()] = auth.HandlerProvider(core.NewHandlerProvider(schemes, provider))
		r = r.WithContext(hosting.ContextWithScope(r.Context(), provider))
		core.Middleware(schemes, logger, "")(endpoint).ServeHTTP(w, r)
	}))
	t.Cleanup(s.server.Close)
	return s
}

// token signs an access token valid for 30 minutes from the scene clock,
// carrying cnf when it is not nil.
func (s *dpopScene) token(t *testing.T, cnf any) string {
	t.Helper()
	return s.tokenWith(t, s.tokenKey, cnf, s.clock.Now().Add(30*time.Minute))
}

func (s *dpopScene) tokenWith(t *testing.T, key jwk.Key, cnf any, expires time.Time) string {
	t.Helper()
	tok := jwxjwt.New()
	require.NoError(t, tok.Set(jwxjwt.IssuerKey, testIssuer))
	require.NoError(t, tok.Set(jwxjwt.AudienceKey, testAudience))
	require.NoError(t, tok.Set(jwxjwt.ExpirationKey, expires))
	require.NoError(t, tok.Set(claims.NameIdentifier, testSubject))
	if cnf != nil {
		require.NoError(t, tok.Set("cnf", cnf))
	}
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
	return string(signed)
}

// bound is the cnf binding a token to the scene proof key.
func (s *dpopScene) bound() map[string]any {
	return map[string]any{"jkt": s.proofKey.thumbprint}
}

// proof signs a proof for a GET of the resource presenting token, with a
// fresh jti; mutate adjusts the claims (a nil value deletes one).
func (s *dpopScene) proof(t *testing.T, signer proofSigner, token string, mutate map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"jti": fmt.Sprintf("proof-%d", s.proofCount.Add(1)),
		"htm": http.MethodGet,
		"htu": s.server.URL + dpopResourcePath,
		"iat": s.clock.Now().Unix(),
		"ath": dpop.AccessTokenHash(token),
	}
	for name, value := range mutate {
		if value == nil {
			delete(claims, name)
			continue
		}
		claims[name] = value
	}
	return signer.sign(t, claims)
}

type wireResponse struct {
	status       int
	challenge    []string
	nonce        []string
	cacheControl string
	body         string
}

// get requests the resource with the given Authorization header (none when
// empty) and DPoP header values.
func (s *dpopScene) get(t *testing.T, authorization string, proofs ...string) wireResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, s.server.URL+dpopResourcePath, nil)
	require.NoError(t, err)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	for _, proof := range proofs {
		request.Header.Add("DPoP", proof)
	}
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return wireResponse{
		status:       response.StatusCode,
		challenge:    response.Header.Values("WWW-Authenticate"),
		nonce:        response.Header.Values("DPoP-Nonce"),
		cacheControl: response.Header.Get("Cache-Control"),
		body:         string(body),
	}
}

func requireChallenge(t *testing.T, got wireResponse, status int, challenge string) {
	t.Helper()
	require.Equal(t, status, got.status)
	require.Equal(t, []string{challenge}, got.challenge)
	require.Equal(t, "no-store", got.cacheControl)
	require.Empty(t, got.body)
}

func requireUnavailable(t *testing.T, got wireResponse) {
	t.Helper()
	require.Equal(t, http.StatusInternalServerError, got.status)
	require.Empty(t, got.challenge)
	require.Equal(t, "no-store", got.cacheControl)
	require.Empty(t, got.body)
}

const (
	challengeInvalidProof   = `DPoP error="invalid_dpop_proof", ` + dpopAlgs
	challengeInvalidToken   = `DPoP error="invalid_token", ` + dpopAlgs
	challengeInvalidRequest = `DPoP error="invalid_request", ` + dpopAlgs
	challengeUseNonce       = `DPoP error="use_dpop_nonce", error_description="DPoP proof must carry the server nonce", ` + dpopAlgs
	challengeNoToken        = `DPoP ` + dpopAlgs
)

func TestDPoPValidationAcceptsBoundTokens(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		scheme string
		iat    func(*dpopScene) int64
	}{
		"canonical scheme":                 {scheme: "DPoP "},
		"lower case scheme and two spaces": {scheme: "dpop  "},
		"iat inside the clock skew": {scheme: "DPoP ", iat: func(s *dpopScene) int64 {
			return s.clock.Now().Add(dpop.DefaultOptions().ClockSkew - time.Second).Unix()
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newDPoPScene(t, sceneConfig{})
			token := s.token(t, s.bound())
			mutate := map[string]any{}
			if tc.iat != nil {
				mutate["iat"] = tc.iat(s)
			}
			got := s.get(t, tc.scheme+token, s.proof(t, s.proofKey, token, mutate))
			require.Equal(t, http.StatusOK, got.status)
			require.Equal(t, 1, s.registry.count())
		})
	}
}

func TestDPoPValidationRefusesRequests(t *testing.T) {
	t.Parallel()
	skew := dpop.DefaultOptions().ClockSkew
	lifetime := dpop.DefaultOptions().ProofLifetime
	type request struct {
		authorization string
		proofs        []string
	}
	cases := map[string]struct {
		configure func(*jwt.Options)
		build     func(t *testing.T, s *dpopScene) request
		status    int
		challenge string
	}{
		"no proof": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "DPoP " + s.token(t, s.bound())}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"two proofs": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil), s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"ath of another token": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, map[string]any{"ath": dpop.AccessTokenHash("other")})}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"no ath": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, map[string]any{"ath": nil})}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"htm POST": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, map[string]any{"htm": http.MethodPost})}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"htu of another path": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, map[string]any{"htu": s.server.URL + "/api/other"})}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"iat too old": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				iat := s.clock.Now().Add(-lifetime - skew - time.Second).Unix()
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, map[string]any{"iat": iat})}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"iat too new": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				iat := s.clock.Now().Add(skew + time.Second).Unix()
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, map[string]any{"iat": iat})}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidProof,
		},
		"proof signed with another key": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				return request{"DPoP " + token, []string{s.proof(t, newProofSigner(t), token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"unbound token with the DPoP scheme": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, nil)
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"bound token as a bearer token": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "Bearer " + s.token(t, s.bound())}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"bound token as a bearer token with a proof": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, s.bound())
				return request{"Bearer " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"cnf a string with the DPoP scheme": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, "not-an-object")
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"cnf a string as a bearer token": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "Bearer " + s.token(t, "not-an-object")}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"numeric jkt with the DPoP scheme": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, map[string]any{"jkt": 12})
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"numeric jkt as a bearer token": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "Bearer " + s.token(t, map[string]any{"jkt": 12})}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"empty jkt with the DPoP scheme": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, map[string]any{"jkt": ""})
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"empty jkt as a bearer token": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "Bearer " + s.token(t, map[string]any{"jkt": ""})}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"token with a wrong signature": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.tokenWith(t, newSigningKey(t, strings.Repeat("e", 128), testKid), s.bound(), s.clock.Now().Add(time.Hour))
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"expired token": {
			build: func(t *testing.T, s *dpopScene) request {
				token := s.tokenWith(t, s.tokenKey, s.bound(), s.clock.Now().Add(-time.Hour))
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"certificate and DPoP binding without the certificate": {
			configure: func(o *jwt.Options) { o.CertificateBindingSource = fixedCertificates(nil) },
			build: func(t *testing.T, s *dpopScene) request {
				token := s.token(t, map[string]any{"jkt": s.proofKey.thumbprint, "x5t#S256": "certificate-thumbprint"})
				return request{"DPoP " + token, []string{s.proof(t, s.proofKey, token, nil)}}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"custom validator token": {
			configure: func(o *jwt.Options) { o.SecurityTokenValidators = []jwt.SecurityTokenValidator{foreignValidator{}} },
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "Bearer opaque-token"}
			},
			status: http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
		"DPoP scheme without a token": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "DPoP"}
			},
			status: http.StatusBadRequest, challenge: challengeInvalidRequest,
		},
		"DPoP scheme with whitespace in the token": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{authorization: "DPoP a b"}
			},
			status: http.StatusBadRequest, challenge: challengeInvalidRequest,
		},
		"no authorization": {
			build: func(t *testing.T, s *dpopScene) request {
				return request{}
			},
			status: http.StatusUnauthorized, challenge: challengeNoToken,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newDPoPScene(t, sceneConfig{configure: tc.configure})
			req := tc.build(t, s)
			got := s.get(t, req.authorization, req.proofs...)
			requireChallenge(t, got, tc.status, tc.challenge)
			require.Empty(t, got.nonce)
			require.Zero(t, s.registry.count(), "a refused request must not register its proof")
		})
	}
}

func TestDPoPValidationAcceptsUnboundBearerTokens(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{})
	token := s.token(t, nil)
	require.Equal(t, http.StatusOK, s.get(t, "Bearer "+token).status)
	require.Equal(t, http.StatusOK, s.get(t, "Bearer "+token, s.proof(t, s.proofKey, token, nil)).status)
	require.Equal(t, http.StatusOK, s.get(t, "Bearer "+s.token(t, map[string]any{"x5t#S256": "abc"})).status)
	require.Zero(t, s.registry.count())
}

func TestDPoPValidationTreatsAnEventTokenAsBearer(t *testing.T) {
	t.Parallel()
	var token string
	s := newDPoPScene(t, sceneConfig{configure: func(o *jwt.Options) {
		events := jwt.NewEvents()
		events.OnMessageReceived = func(ctx *jwt.MessageReceivedContext) error {
			ctx.Token = token
			return nil
		}
		o.SetEvents(events)
	}})
	token = s.token(t, s.bound())
	got := s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil))
	requireChallenge(t, got, http.StatusUnauthorized, challengeInvalidToken)
	require.Zero(t, s.registry.count())
}

func TestDPoPValidationRefusesAReplayedProof(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{})
	token := s.token(t, s.bound())
	proof := s.proof(t, s.proofKey, token, nil)
	require.Equal(t, http.StatusOK, s.get(t, "DPoP "+token, proof).status)
	requireChallenge(t, s.get(t, "DPoP "+token, proof), http.StatusUnauthorized, challengeInvalidProof)
}

func TestDPoPValidationRegistersOncePerAuthentication(t *testing.T) {
	t.Parallel()
	var validated atomic.Int64
	s := newDPoPScene(t, sceneConfig{configure: func(o *jwt.Options) {
		o.SecurityTokenValidators = []jwt.SecurityTokenValidator{jwt.NewSecurityTokenHandler(), jwt.NewSecurityTokenHandler()}
		events := jwt.NewEvents()
		events.OnTokenValidated = func(*jwt.TokenValidatedContext) error {
			if validated.Add(1) == 1 {
				return errors.New("first validation refused by the application")
			}
			return nil
		}
		o.SetEvents(events)
	}})
	token := s.token(t, s.bound())
	require.Equal(t, http.StatusOK, s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil)).status)
	require.EqualValues(t, 2, validated.Load())
	require.Equal(t, 1, s.registry.count())
}

func TestDPoPValidationRegistryFailure(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{})
	s.registry.fail()
	token := s.token(t, s.bound())
	requireUnavailable(t, s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil)))

	keys, _ := s.registry.registrations()
	require.Len(t, keys, 1)
	logs := s.logs.String()
	require.NotContains(t, logs, keys[0], "no log may carry the registry key")
	require.Contains(t, logs, "level=ERROR")
	require.Contains(t, logs, "error_type=jwt_test.registryDown")
	require.NotContains(t, logs, "registry down")
}

func TestDPoPValidationNotMadeByTheConstructor(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{validation: func(*dpopScene) *jwt.DPoPValidation { return &jwt.DPoPValidation{} }})
	token := s.token(t, nil)
	requireUnavailable(t, s.get(t, "Bearer "+token))
	requireUnavailable(t, s.get(t, ""))
}

func TestDPoPValidationOff(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{off: true})
	token := s.token(t, s.bound())
	got := s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil))
	require.Equal(t, http.StatusUnauthorized, got.status)
	require.Empty(t, got.challenge)
	require.Empty(t, got.nonce)
	require.Empty(t, got.cacheControl)
	require.Equal(t, http.StatusUnauthorized, s.get(t, "").status)
	require.Empty(t, s.get(t, "").challenge)
	require.Zero(t, s.registry.count())

	// The DPoP scheme is not read at all: the handler finds no token.
	var failure error
	response := serve(t, newTestOptions(t, keySet(t, s.tokenKey), nil), "DPoP "+token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if result := core.ResultFromContext(r.Context()); result != nil {
			failure = errors.New("unexpected authentication result")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	require.Equal(t, http.StatusNoContent, response.Code)
	require.NoError(t, failure)
}

func TestDPoPValidationNonceMode(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{requireNonce: true})
	token := s.token(t, s.bound())

	first := s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil))
	requireChallenge(t, first, http.StatusUnauthorized, challengeUseNonce)
	require.Len(t, first.nonce, 1)
	require.NotEmpty(t, first.nonce[0])
	require.Zero(t, s.registry.count())

	second := s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, map[string]any{"nonce": first.nonce[0]}))
	require.Equal(t, http.StatusOK, second.status)
	require.Empty(t, second.nonce, "a successful response carries no nonce")
	_, expiries := s.registry.registrations()
	require.Len(t, expiries, 1)
	options := dpop.DefaultOptions()
	// The nonce deadline (issued now, plus its lifetime) is later than the
	// iat deadline and now, so it bounds the record.
	require.True(t, expiries[0].Equal(dpopTestNow.Add(options.NonceLifetime).Add(options.ClockSkew)), "expiry = %s", expiries[0])
}

func TestDPoPValidationNonceModeRefusals(t *testing.T) {
	t.Parallel()
	options := dpop.DefaultOptions()
	cases := map[string]struct {
		nonce     func(t *testing.T, s *dpopScene) string
		unbound   bool
		status    int
		challenge string
	}{
		"expired nonce": {
			nonce: func(t *testing.T, s *dpopScene) string {
				issued := s.issue(t, "resource-server https://api.example", dpopTestNow)
				s.clock.set(dpopTestNow.Add(options.NonceLifetime + options.ClockSkew + time.Second))
				return issued
			},
			status: http.StatusUnauthorized, challenge: challengeUseNonce,
		},
		"authorization server nonce": {
			nonce: func(t *testing.T, s *dpopScene) string {
				return s.issue(t, "authorization-server https://api.example", dpopTestNow)
			},
			status: http.StatusUnauthorized, challenge: challengeUseNonce,
		},
		"nonce of another resource": {
			nonce: func(t *testing.T, s *dpopScene) string {
				return s.issue(t, "resource-server https://other.example", dpopTestNow)
			},
			status: http.StatusUnauthorized, challenge: challengeUseNonce,
		},
		"accepted nonce but an unbound token": {
			nonce: func(t *testing.T, s *dpopScene) string {
				return s.issue(t, "resource-server https://api.example", dpopTestNow)
			},
			unbound: true,
			status:  http.StatusUnauthorized, challenge: challengeInvalidToken,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newDPoPScene(t, sceneConfig{requireNonce: true})
			nonce := tc.nonce(t, s)
			cnf := any(s.bound())
			if tc.unbound {
				cnf = nil
			}
			token := s.token(t, cnf)
			got := s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, map[string]any{"nonce": nonce}))
			requireChallenge(t, got, tc.status, tc.challenge)
			require.Len(t, got.nonce, 1, "every 401 challenge carries a fresh nonce")
			require.Zero(t, s.registry.count())
		})
	}

	t.Run("no token", func(t *testing.T) {
		t.Parallel()
		s := newDPoPScene(t, sceneConfig{requireNonce: true})
		got := s.get(t, "")
		requireChallenge(t, got, http.StatusUnauthorized, challengeNoToken)
		require.Len(t, got.nonce, 1)
	})
	t.Run("malformed header carries no nonce", func(t *testing.T) {
		t.Parallel()
		s := newDPoPScene(t, sceneConfig{requireNonce: true})
		got := s.get(t, "DPoP a b")
		requireChallenge(t, got, http.StatusBadRequest, challengeInvalidRequest)
		require.Empty(t, got.nonce)
	})
}

func TestDPoPValidationNonceKeySourceFailure(t *testing.T) {
	t.Parallel()
	t.Run("checking a nonce", func(t *testing.T) {
		t.Parallel()
		s := newDPoPScene(t, sceneConfig{requireNonce: true})
		nonce := s.issue(t, "resource-server https://api.example", dpopTestNow)
		s.nonceKeys.failing.Store(true)
		token := s.token(t, s.bound())
		requireUnavailable(t, s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, map[string]any{"nonce": nonce})))
		require.Zero(t, s.registry.count())
		require.NotContains(t, s.logs.String(), "key vault unreachable")
		require.Contains(t, s.logs.String(), "error_type=*errors.errorString")
	})
	t.Run("issuing a nonce", func(t *testing.T) {
		t.Parallel()
		s := newDPoPScene(t, sceneConfig{requireNonce: true})
		s.nonceKeys.failing.Store(true)
		token := s.token(t, s.bound())
		requireUnavailable(t, s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil)))
	})
}

// issue returns a nonce for surface issued with the scene nonce keys.
func (s *dpopScene) issue(t *testing.T, surface string, at time.Time) string {
	t.Helper()
	nonce, err := dpop.NewNonceSealer(s.nonceKeys, s.options).Issue(surface, at)
	require.NoError(t, err)
	return nonce
}

type failingNonceKeys struct{}

func (failingNonceKeys) NonceKeys() (dpop.NonceKey, []dpop.NonceKey, error) {
	return dpop.NonceKey{}, nil, errors.New("unavailable")
}

type fixedNonceKeys struct{ current dpop.NonceKey }

func (f fixedNonceKeys) NonceKeys() (dpop.NonceKey, []dpop.NonceKey, error) {
	return f.current, nil, nil
}

func TestNewDPoPValidationRefusesConfigurations(t *testing.T) {
	t.Parallel()
	registry := replay.NewMemoryRegistry()
	keys, err := dpop.NewStaticNonceKeys(dpop.NonceKey{Id: "k1", Secret: bytes.Repeat([]byte{1}, 32)})
	require.NoError(t, err)
	nonceMode := dpop.Options{RequireNonce: true}
	cases := map[string]jwt.DPoPValidationConfig{
		"no registry":                 {Options: dpop.Options{}},
		"invalid options":             {Options: dpop.Options{SigningAlgorithms: []string{"HS256"}}, Registry: registry},
		"negative lifetime":           {Options: dpop.Options{ProofLifetime: -time.Second}, Registry: registry},
		"nonce mode without keys":     {Options: nonceMode, Registry: registry, Resource: "https://api.example"},
		"nonce mode keys unavailable": {Options: nonceMode, Registry: registry, NonceKeys: failingNonceKeys{}, Resource: "https://api.example"},
		"nonce mode invalid keys": {
			Options: nonceMode, Registry: registry, Resource: "https://api.example",
			NonceKeys: fixedNonceKeys{current: dpop.NonceKey{Id: "k1", Secret: []byte("short")}},
		},
		"nonce mode without resource": {Options: nonceMode, Registry: registry, NonceKeys: keys},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validation, err := jwt.NewDPoPValidation(config)
			require.ErrorIs(t, err, jwt.ErrInvalidDPoPConfiguration)
			require.Nil(t, validation)
		})
	}
}

func TestNewDPoPValidationAcceptsConfigurations(t *testing.T) {
	t.Parallel()
	registry := replay.NewMemoryRegistry()
	cases := map[string]jwt.DPoPValidationConfig{
		"iat mode":                         {Registry: registry},
		"iat mode ignores the nonce input": {Registry: registry, NonceKeys: failingNonceKeys{}},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			validation, err := jwt.NewDPoPValidation(config)
			require.NoError(t, err)
			require.NotNil(t, validation)
		})
	}
}

func TestDPoPValidationRequestUri(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{validation: func(s *dpopScene) *jwt.DPoPValidation {
		validation, err := jwt.NewDPoPValidation(jwt.DPoPValidationConfig{
			Options:    s.options,
			Registry:   s.registry,
			RequestUri: func(r *http.Request) string { return "https://public.example/edge" + r.URL.Path },
		})
		require.NoError(t, err)
		return validation
	}})
	token := s.token(t, s.bound())
	requireChallenge(t, s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil)), http.StatusUnauthorized, challengeInvalidProof)
	proof := s.proof(t, s.proofKey, token, map[string]any{"htu": "https://public.example/edge" + dpopResourcePath})
	require.Equal(t, http.StatusOK, s.get(t, "DPoP "+token, proof).status)
}

func TestDPoPValidationChallengeAfterSuccess(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{alwaysChallenge: true})
	token := s.token(t, s.bound())
	got := s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil))
	requireChallenge(t, got, http.StatusUnauthorized, challengeNoToken)
	require.Equal(t, 1, s.registry.count(), "the challenge reuses the memoized result and registers nothing more")
}

func TestDPoPValidationChallengeAfterAnEventError(t *testing.T) {
	t.Parallel()
	s := newDPoPScene(t, sceneConfig{configure: func(o *jwt.Options) {
		events := jwt.NewEvents()
		events.OnMessageReceived = func(*jwt.MessageReceivedContext) error {
			return errors.New("message refused by the application")
		}
		o.SetEvents(events)
	}})
	token := s.token(t, s.bound())
	got := s.get(t, "DPoP "+token, s.proof(t, s.proofKey, token, nil))
	requireChallenge(t, got, http.StatusUnauthorized, challengeInvalidToken)
	require.Zero(t, s.registry.count())
}
