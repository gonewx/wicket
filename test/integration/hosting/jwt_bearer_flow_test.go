//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/jwt"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/di"
	svcimpl "github.com/gonewx/wicket/services/impl"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

// These guards exercise the JWT bearer scheme through the *real composition
// root* rather than the hand-built provider double used by the package-level
// contract tests. The path under test is the one host code actually walks:
//   di.NewRoot()  →  ServerConfig.SetAuthenticationHandlerProvider (the seam the
//   keyed jwt factory at di/core.go:271 consults first)  →  the container-scoped
//   auth.SchemeProvider / auth.HandlerProvider  →  authcore.Service.Authenticate.
// A bearer token is signed in-test with a symmetric HS256 key; the same key is
// loaded into the seam handler's TokenValidationParameters. Only the composition
// wiring is new here — token issuance mirrors the auth/jwt contract suite.

const (
	jwtE2EIssuer   = "issuer.contoso.com"
	jwtE2EAudience = "audience.contoso.com"
	jwtE2ESubject  = "Bob"
	jwtE2EKid      = "e2e-key"
)

// newJWTSigningKey returns a deterministic symmetric HS256 jwk carrying a fixed
// key id. The raw material is a fixed 128-byte block so signing and verification
// are fully reproducible across runs.
func newJWTSigningKey(t *testing.T, raw string) jwk.Key {
	t.Helper()
	key, err := jwk.Import([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, jwtE2EKid))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.HS256()))
	return key
}

// signJWTE2EToken builds a bearer token with the standard issuer/audience/subject
// and a +30m expiry, letting a mutator override individual claims before signing.
func signJWTE2EToken(t *testing.T, key jwk.Key, mutate func(jwxjwt.Token)) string {
	t.Helper()
	tok := jwxjwt.New()
	require.NoError(t, tok.Set(jwxjwt.IssuerKey, jwtE2EIssuer))
	require.NoError(t, tok.Set(jwxjwt.AudienceKey, jwtE2EAudience))
	require.NoError(t, tok.Set(jwxjwt.ExpirationKey, time.Now().Add(30*time.Minute)))
	require.NoError(t, tok.Set(claims.NameIdentifier, jwtE2ESubject))
	if mutate != nil {
		mutate(tok)
	}
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
	return string(signed)
}

// installJWTSeamHandler wires a bearer handler backed by verifyKeys through the
// ServerConfig seam, so the container's keyed jwt factory resolves it in place of
// the default handler whose validation parameters carry no verification key. The
// configure hook lets a caller flip handler options (SaveToken, validators) before
// the handler is built.
func installJWTSeamHandler(t *testing.T, root *di.Root, verifyKeys jwk.Set, configure func(*jwt.Options)) {
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
		if configure != nil {
			configure(opts)
		}
		return jwt.NewHandler(staticJWTMonitor{opts: opts}, discardJWTLogger(t), svcimpl.SystemClock{})
	})
	require.NoError(t, godi.GetRequired[auth.SchemeProvider](root).AddScheme(auth.NewScheme(wicket.JwtBearerAuthenticationScheme, "handler")))
}

// staticJWTMonitor hands the seam handler a fixed options instance, standing in
// for the runtime OptionsMonitor the container would otherwise supply.
type staticJWTMonitor struct {
	opts *jwt.Options
}

func (m staticJWTMonitor) CurrentValue() (*jwt.Options, error) { return m.opts, nil }
func (m staticJWTMonitor) Get(string) (*jwt.Options, error)    { return m.opts, nil }

// discardJWTLogger returns a logger that drops every record, keeping the seam
// handler's debug output out of the test log.
func discardJWTLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestJWTBearerAuthenticatesThroughCompositionRootE2E is the primary end-to-end
// guard: a token signed with the verification key drives a full authentication
// through the container-resolved service and yields a succeeded result whose
// principal carries the subject; a missing, foreign-signed, or expired token is
// denied.
func TestJWTBearerAuthenticatesThroughCompositionRootE2E(t *testing.T) {
	t.Parallel()

	signingKey := newJWTSigningKey(t, strings.Repeat("a", 128))
	verifyKeys := jwk.NewSet()
	require.NoError(t, verifyKeys.AddKey(signingKey))

	// A key with the same id but different material forces a signature mismatch.
	wrongKey := newJWTSigningKey(t, strings.Repeat("b", 128))

	tests := map[string]struct {
		authHeader    func() string
		wantSucceeded bool
	}{
		"valid bearer token authenticates": {
			authHeader:    func() string { return "Bearer " + signJWTE2EToken(t, signingKey, nil) },
			wantSucceeded: true,
		},
		"missing authorization header is anonymous": {
			authHeader:    func() string { return "" },
			wantSucceeded: false,
		},
		"foreign-signed token is denied": {
			authHeader:    func() string { return "Bearer " + signJWTE2EToken(t, wrongKey, nil) },
			wantSucceeded: false,
		},
		"expired token is denied": {
			authHeader: func() string {
				return "Bearer " + signJWTE2EToken(t, signingKey, func(tok jwxjwt.Token) {
					_ = tok.Set(jwxjwt.ExpirationKey, time.Now().Add(-1*time.Minute))
				})
			},
			wantSucceeded: false,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := newAuthRoot(t)
			installJWTSeamHandler(t, root, verifyKeys, nil)

			scope := root.CreateScope()
			defer scope.Close()
			service := godi.GetRequired[*authcore.Service](scope)

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			if header := tc.authHeader(); header != "" {
				request.Header.Set("Authorization", header)
			}
			response := httptest.NewRecorder()

			result, err := service.Authenticate(request, response, wicket.JwtBearerAuthenticationScheme)
			require.NoError(t, err)
			require.NotNil(t, result)

			require.Equal(t, tc.wantSucceeded, result.Succeeded())
			if tc.wantSucceeded {
				require.NotNil(t, result.Principal)
				subject := result.Principal.FindFirst(claims.NameIdentifier)
				require.NotNil(t, subject, "an authenticated principal must expose the subject identifier")
				require.Equal(t, jwtE2ESubject, subject.Value)
			}
		})
	}
}

// TestJWTBearerSaveTokenThroughCompositionRootE2E guards that SaveToken persists
// the raw bearer token under access_token in the authentication properties when
// the handler is resolved through the real container.
func TestJWTBearerSaveTokenThroughCompositionRootE2E(t *testing.T) {
	t.Parallel()

	signingKey := newJWTSigningKey(t, strings.Repeat("a", 128))
	verifyKeys := jwk.NewSet()
	require.NoError(t, verifyKeys.AddKey(signingKey))

	root := newAuthRoot(t)
	installJWTSeamHandler(t, root, verifyKeys, func(o *jwt.Options) {
		o.SaveToken = true
	})

	scope := root.CreateScope()
	defer scope.Close()
	service := godi.GetRequired[*authcore.Service](scope)

	token := signJWTE2EToken(t, signingKey, nil)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()

	result, err := service.Authenticate(request, response, wicket.JwtBearerAuthenticationScheme)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.Succeeded())

	stored, err := auth.GetTokenValue(result.Properties, "access_token")
	require.NoError(t, err)
	require.Equal(t, token, stored, "the persisted token must match the presented bearer token byte-for-byte")
}

// TestJWTBearerHandlerResolvesFromContainerDefaultFactoryE2E guards the DI
// registration itself, independent of the seam: with no host-provided handler,
// the keyed jwt factory (di/core.go:271) still resolves a usable *jwt.Handler
// bound to the requested scheme. The default handler carries no verification key,
// so its authentication outcome is not asserted here — only that the container
// produces the concrete jwt handler for the bearer scheme.
func TestJWTBearerHandlerResolvesFromContainerDefaultFactoryE2E(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	require.NoError(t, godi.GetRequired[auth.SchemeProvider](root).AddScheme(auth.NewScheme(wicket.JwtBearerAuthenticationScheme, "handler")))

	scope := root.CreateScope()
	defer scope.Close()

	handler := godi.GetRequiredKeyed[auth.Handler](scope, wicket.JwtBearerAuthenticationScheme)
	require.NotNil(t, handler, "the container must resolve a handler for the bearer scheme")
	_, ok := handler.(*jwt.Handler)
	require.True(t, ok, "the default keyed factory must resolve the concrete jwt handler, got %T", handler)
}
