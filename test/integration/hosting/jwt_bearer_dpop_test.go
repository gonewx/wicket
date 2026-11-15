//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/jwt"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/replay"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// These guards drive DPoP validation of the JWT bearer scheme through the real
// composition root: the host builds the validation with jwt.NewDPoPValidation,
// passing an in-memory replay registry explicitly, hangs it on the options of
// the handler it installs through the ServerConfig seam, and serves a protected
// endpoint on an httptest.Server that authenticates through the scoped
// authcore.Service and challenges the scheme when the request did not
// authenticate.

// dpopFlowNow is the fixed instant of the handler clock.
var dpopFlowNow = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

const dpopFlowPath = "/api/orders"

type fixedFlowClock struct{ now time.Time }

func (c fixedFlowClock) Now() time.Time { return c.now }

// flowProofKey is a P-256 DPoP proof key.
type flowProofKey struct {
	private    *ecdsa.PrivateKey
	thumbprint string
}

func newFlowProofKey(t *testing.T) flowProofKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	public, err := jwk.Import(&private.PublicKey)
	require.NoError(t, err)
	thumbprint, err := dpop.Thumbprint(public)
	require.NoError(t, err)
	return flowProofKey{private: private, thumbprint: thumbprint}
}

func (k flowProofKey) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	coordinate := func(v []byte) string {
		padded := make([]byte, 32)
		copy(padded[32-len(v):], v)
		return base64.RawURLEncoding.EncodeToString(padded)
	}
	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": coordinate(k.private.X.Bytes()), "y": coordinate(k.private.Y.Bytes())},
	})
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	require.NoError(t, err)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// dpopFlow is one protected resource behind the real composition root.
type dpopFlow struct {
	server     *httptest.Server
	signingKey jwk.Key
	proofKey   flowProofKey
	proofs     atomic.Int64
}

func newDPoPFlow(t *testing.T, config func(registry replay.Registry) jwt.DPoPValidationConfig) *dpopFlow {
	t.Helper()
	flow := &dpopFlow{signingKey: newJWTSigningKey(t, strings.Repeat("a", 128)), proofKey: newFlowProofKey(t)}
	verifyKeys := jwk.NewSet()
	require.NoError(t, verifyKeys.AddKey(flow.signingKey))

	validation, err := jwt.NewDPoPValidation(config(replay.NewMemoryRegistry()))
	require.NoError(t, err)

	root := newAuthRoot(t)
	installDPoPSeamHandler(t, root, verifyKeys, validation)
	flow.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := root.CreateScope()
		defer scope.Close()
		service := godi.GetRequired[*authcore.Service](scope)
		result, err := service.Authenticate(r, w, wicket.JwtBearerAuthenticationScheme)
		if err == nil && result != nil && result.Succeeded() && result.Principal.FindFirst(claims.NameIdentifier) != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		if err := service.Challenge(r, w, wicket.JwtBearerAuthenticationScheme, nil); err != nil {
			t.Errorf("Challenge: %v", err)
		}
	}))
	t.Cleanup(flow.server.Close)
	return flow
}

// installDPoPSeamHandler wires a bearer handler with DPoP validation through
// the ServerConfig seam, the way installJWTSeamHandler does without it.
func installDPoPSeamHandler(t *testing.T, root *di.Root, verifyKeys jwk.Set, validation *jwt.DPoPValidation) {
	t.Helper()
	root.ServerConfig().SetAuthenticationHandlerProvider(wicket.JwtBearerAuthenticationScheme, func(p godi.Provider) auth.Handler {
		opts := jwt.NewOptions()
		opts.TokenValidationParameters = &jwt.TokenValidationParameters{
			ValidIssuer:         jwtE2EIssuer,
			ValidAudience:       jwtE2EAudience,
			Keys:                verifyKeys,
			RequireSignedTokens: true,
			ValidateLifetime:    true,
		}
		opts.DPoP = validation
		return jwt.NewHandler(staticJWTMonitor{opts: opts}, discardJWTLogger(t), fixedFlowClock{now: dpopFlowNow})
	})
	require.NoError(t, godi.GetRequired[auth.SchemeProvider](root).AddScheme(auth.NewScheme(wicket.JwtBearerAuthenticationScheme, "handler")))
}

// token signs an access token valid for 30 minutes after the handler clock,
// bound to the flow proof key when bound is set.
func (f *dpopFlow) token(t *testing.T, bound bool) string {
	t.Helper()
	tok := jwxjwt.New()
	require.NoError(t, tok.Set(jwxjwt.IssuerKey, jwtE2EIssuer))
	require.NoError(t, tok.Set(jwxjwt.AudienceKey, jwtE2EAudience))
	require.NoError(t, tok.Set(jwxjwt.ExpirationKey, dpopFlowNow.Add(30*time.Minute)))
	require.NoError(t, tok.Set(claims.NameIdentifier, jwtE2ESubject))
	if bound {
		require.NoError(t, tok.Set("cnf", map[string]any{"jkt": f.proofKey.thumbprint}))
	}
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.HS256(), f.signingKey))
	require.NoError(t, err)
	return string(signed)
}

// proof signs a GET proof for the resource presenting token with key; extra
// claims are added or replace the defaults.
func (f *dpopFlow) proof(t *testing.T, key flowProofKey, token string, extra map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"jti": fmt.Sprintf("flow-proof-%d", f.proofs.Add(1)),
		"htm": http.MethodGet,
		"htu": f.server.URL + dpopFlowPath,
		"iat": dpopFlowNow.Unix(),
		"ath": dpop.AccessTokenHash(token),
	}
	for name, value := range extra {
		claims[name] = value
	}
	return key.sign(t, claims)
}

type flowResponse struct {
	status    int
	challenge []string
	nonce     string
}

func (f *dpopFlow) get(t *testing.T, authorization string, proof string) flowResponse {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, f.server.URL+dpopFlowPath, nil)
	require.NoError(t, err)
	request.Header.Set("Authorization", authorization)
	if proof != "" {
		request.Header.Set("DPoP", proof)
	}
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	return flowResponse{
		status:    response.StatusCode,
		challenge: response.Header.Values("WWW-Authenticate"),
		nonce:     response.Header.Get("DPoP-Nonce"),
	}
}

func iatModeConfig(registry replay.Registry) jwt.DPoPValidationConfig {
	return jwt.DPoPValidationConfig{
		Options:  dpop.Options{SigningAlgorithms: []string{"ES256"}},
		Registry: registry,
	}
}

func TestJWTBearerDPoPIatModeThroughCompositionRoot(t *testing.T) {
	t.Parallel()
	const (
		invalidProof = `DPoP error="invalid_dpop_proof", algs="ES256"`
		invalidToken = `DPoP error="invalid_token", algs="ES256"`
	)

	t.Run("valid proof then its replay", func(t *testing.T) {
		t.Parallel()
		flow := newDPoPFlow(t, iatModeConfig)
		token := flow.token(t, true)
		proof := flow.proof(t, flow.proofKey, token, nil)
		require.Equal(t, http.StatusOK, flow.get(t, "DPoP "+token, proof).status)
		replayed := flow.get(t, "DPoP "+token, proof)
		require.Equal(t, http.StatusUnauthorized, replayed.status)
		require.Equal(t, []string{invalidProof}, replayed.challenge)
	})

	cases := map[string]struct {
		request   func(t *testing.T, flow *dpopFlow) (string, string)
		challenge string
	}{
		"ath of another token": {
			request: func(t *testing.T, flow *dpopFlow) (string, string) {
				token := flow.token(t, true)
				return "DPoP " + token, flow.proof(t, flow.proofKey, token, map[string]any{"ath": dpop.AccessTokenHash("another-token")})
			},
			challenge: invalidProof,
		},
		"proof key not the bound one": {
			request: func(t *testing.T, flow *dpopFlow) (string, string) {
				token := flow.token(t, true)
				return "DPoP " + token, flow.proof(t, newFlowProofKey(t), token, nil)
			},
			challenge: invalidToken,
		},
		"bound token as a bearer token": {
			request: func(t *testing.T, flow *dpopFlow) (string, string) {
				return "Bearer " + flow.token(t, true), ""
			},
			challenge: invalidToken,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			flow := newDPoPFlow(t, iatModeConfig)
			authorization, proof := tc.request(t, flow)
			got := flow.get(t, authorization, proof)
			require.Equal(t, http.StatusUnauthorized, got.status)
			require.Equal(t, []string{tc.challenge}, got.challenge)
		})
	}

	t.Run("unbound bearer token still passes", func(t *testing.T) {
		t.Parallel()
		flow := newDPoPFlow(t, iatModeConfig)
		require.Equal(t, http.StatusOK, flow.get(t, "Bearer "+flow.token(t, false), "").status)
	})
}

func TestJWTBearerDPoPNonceModeThroughCompositionRoot(t *testing.T) {
	t.Parallel()
	keys, err := dpop.NewStaticNonceKeys(dpop.NonceKey{Id: "rs-1", Secret: bytes.Repeat([]byte{9}, 32)})
	require.NoError(t, err)
	flow := newDPoPFlow(t, func(registry replay.Registry) jwt.DPoPValidationConfig {
		return jwt.DPoPValidationConfig{
			Options:   dpop.Options{SigningAlgorithms: []string{"ES256"}, RequireNonce: true},
			Registry:  registry,
			NonceKeys: keys,
			Resource:  "https://orders.example",
		}
	})
	token := flow.token(t, true)

	challenged := flow.get(t, "DPoP "+token, flow.proof(t, flow.proofKey, token, nil))
	require.Equal(t, http.StatusUnauthorized, challenged.status)
	require.Equal(t, []string{`DPoP error="use_dpop_nonce", error_description="DPoP proof must carry the server nonce", algs="ES256"`}, challenged.challenge)
	require.NotEmpty(t, challenged.nonce)

	accepted := flow.get(t, "DPoP "+token, flow.proof(t, flow.proofKey, token, map[string]any{"nonce": challenged.nonce}))
	require.Equal(t, http.StatusOK, accepted.status)
}
