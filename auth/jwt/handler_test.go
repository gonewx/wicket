// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/auth/jwt"
	"github.com/gonewx/wicket/claims"
	optspkg "github.com/gonewx/wicket/di/options"
	"github.com/gonewx/wicket/hosting"
	svcimpl "github.com/gonewx/wicket/services/impl"
	"github.com/stretchr/testify/require"
)

// The bearer contract is exercised end-to-end: a token is signed in-test with a
// symmetric HS256 key, the JWT scheme is assembled by hand around the seam-native
// handler, and the request is driven through core.Middleware so the authentication
// result is observed the way a downstream handler sees it — through
// core.ResultFromContext. Tokens are signed directly with jwx/v2 because
// tokens/jwt carries no issuance helper; the same symmetric key is loaded into a
// jwk.Set for TokenValidationParameters.Keys.

const (
	testIssuer   = "issuer.contoso.com"
	testAudience = "audience.contoso.com"
	testSubject  = "Bob"
	testKid      = "test-key"
)

// newSigningKey returns a symmetric HS256 jwk carrying a fixed key id. The raw
// material is a fixed 128-byte block so signing and verification are fully
// deterministic.
func newSigningKey(t *testing.T, raw string, kid string) jwk.Key {
	t.Helper()
	key, err := jwk.Import([]byte(raw))
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.HS256()))
	return key
}

// keySet wraps a single key in a jwk.Set for TokenValidationParameters.Keys.
func keySet(t *testing.T, keys ...jwk.Key) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		require.NoError(t, set.AddKey(k))
	}
	return set
}

// signToken builds a bearer token with the standard issuer/audience/subject and
// a +30m expiry, letting a mutator override individual claims before signing.
func signToken(t *testing.T, key jwk.Key, mutate func(jwxjwt.Token)) string {
	t.Helper()
	tok := jwxjwt.New()
	require.NoError(t, tok.Set(jwxjwt.IssuerKey, testIssuer))
	require.NoError(t, tok.Set(jwxjwt.AudienceKey, testAudience))
	require.NoError(t, tok.Set(jwxjwt.ExpirationKey, time.Now().Add(30*time.Minute)))
	require.NoError(t, tok.Set(claims.NameIdentifier, testSubject))
	if mutate != nil {
		mutate(tok)
	}
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
	return string(signed)
}

// newTestOptions produces JWT options whose validation parameters expect the
// standard issuer/audience and verify against the supplied key set.
func newTestOptions(t *testing.T, verifyKeys jwk.Set, configure func(*jwt.Options)) *jwt.Options {
	t.Helper()
	opts := jwt.NewOptions()
	opts.TokenValidationParameters = &jwt.TokenValidationParameters{
		ValidIssuer:         testIssuer,
		ValidAudience:       testAudience,
		Keys:                verifyKeys,
		RequireSignedTokens: true,
		ValidateLifetime:    true,
	}
	if configure != nil {
		configure(opts)
	}
	return opts
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// staticOptionsMonitor hands the handler a fixed options instance keyed by
// scheme, standing in for the runtime OptionsMonitor.
type staticOptionsMonitor struct {
	opts *jwt.Options
}

func (m staticOptionsMonitor) CurrentValue() (*jwt.Options, error) { return m.opts, nil }
func (m staticOptionsMonitor) Get(string) (*jwt.Options, error)    { return m.opts, nil }

var _ optspkg.OptionsMonitor[*jwt.Options] = staticOptionsMonitor{}

// keyedProvider is a godi.Scope double that resolves auth.Handler by scheme name
// and exposes the unkeyed HandlerProvider the middleware reads from the scope.
type keyedProvider struct {
	factories map[string]func() auth.Handler
	services  map[reflect.Type]any
}

func newKeyedProvider() *keyedProvider {
	return &keyedProvider{
		factories: map[string]func() auth.Handler{},
		services:  map[reflect.Type]any{},
	}
}

func (p *keyedProvider) GetService(t reflect.Type) any { return p.services[t] }

func (p *keyedProvider) IsService(t reflect.Type) bool {
	_, ok := p.services[t]
	return ok
}

func (p *keyedProvider) IsKeyedService(t reflect.Type, key any) bool {
	if key == nil {
		return p.IsService(t)
	}
	if t == reflect.TypeFor[auth.Handler]() {
		name, ok := key.(string)
		if !ok {
			return false
		}
		_, ok = p.factories[name]
		return ok
	}
	return false
}

func (p *keyedProvider) GetKeyedService(t reflect.Type, key any) any {
	if key == nil {
		return p.GetService(t)
	}
	if t == reflect.TypeFor[auth.Handler]() {
		name, ok := key.(string)
		if !ok {
			return nil
		}
		if factory, ok := p.factories[name]; ok {
			return factory()
		}
	}
	return nil
}

func (p *keyedProvider) GetKeyedServices(reflect.Type, any) []any { return nil }
func (p *keyedProvider) CreateScope() godi.Scope                  { return p }
func (p *keyedProvider) Close() error                             { return nil }

// serve assembles the JWT scheme around the seam-native handler and drives one
// request through core.Middleware, returning the recorder after the downstream
// handler has run.
func serve(t *testing.T, opts *jwt.Options, authHeader string, downstream http.Handler) *httptest.ResponseRecorder {
	t.Helper()

	authOptions := auth.NewOptions()
	authOptions.DefaultAuthenticateScheme = jwt.AuthenticationScheme
	schemes := core.NewSchemeProvider(authOptions)
	require.NoError(t, schemes.AddScheme(auth.NewScheme(jwt.AuthenticationScheme, "handler")))

	provider := newKeyedProvider()
	monitor := staticOptionsMonitor{opts: opts}
	provider.factories[jwt.AuthenticationScheme] = func() auth.Handler {
		return jwt.NewHandler(monitor, discardLogger(), svcimpl.SystemClock{})
	}
	handlers := core.NewHandlerProvider(schemes, provider)
	provider.services[reflect.TypeFor[auth.HandlerProvider]()] = auth.HandlerProvider(handlers)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		request.Header.Set("Authorization", authHeader)
	}
	request = request.WithContext(hosting.ContextWithScope(request.Context(), provider))
	response := httptest.NewRecorder()

	core.Middleware(schemes, discardLogger(), "")(downstream).ServeHTTP(response, request)
	return response
}

// protectedEndpoint returns 200 only when the request carries a succeeded
// authentication result whose principal exposes the subject identifier;
// otherwise it falls back to 401. This is the observable H1 gate.
func protectedEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := core.ResultFromContext(r.Context())
		if result == nil || !result.Succeeded() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if result.Principal.FindFirst(claims.NameIdentifier) == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// TestBearerTokenValidation is contract H1: a valid Bearer token drives
// end-to-end authentication and unlocks a protected endpoint, while a request
// that is missing, malformed, wrongly signed, expired, or unservable by any
// validator is denied.
func TestBearerTokenValidation(t *testing.T) {
	t.Parallel()

	signingKey := newSigningKey(t, strings.Repeat("a", 128), testKid)
	verifyKeys := keySet(t, signingKey)

	// A key with the same id but different material forces a signature mismatch.
	wrongKey := newSigningKey(t, strings.Repeat("b", 128), testKid)

	tests := map[string]struct {
		authHeader     func() string
		noValidators   bool
		wantStatusCode int
	}{
		"valid bearer token is authenticated": {
			authHeader:     func() string { return "Bearer " + signToken(t, signingKey, nil) },
			wantStatusCode: http.StatusOK,
		},
		"missing authorization header is denied": {
			authHeader:     func() string { return "" },
			wantStatusCode: http.StatusUnauthorized,
		},
		"non-bearer authorization scheme is denied": {
			authHeader:     func() string { return "Token " + signToken(t, signingKey, nil) },
			wantStatusCode: http.StatusUnauthorized,
		},
		"token signed with a foreign key is denied": {
			authHeader:     func() string { return "Bearer " + signToken(t, wrongKey, nil) },
			wantStatusCode: http.StatusUnauthorized,
		},
		"expired token is denied": {
			authHeader: func() string {
				return "Bearer " + signToken(t, signingKey, func(tok jwxjwt.Token) {
					_ = tok.Set(jwxjwt.ExpirationKey, time.Now().Add(-1*time.Minute))
				})
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		"issuer mismatch is denied": {
			authHeader: func() string {
				return "Bearer " + signToken(t, signingKey, func(tok jwxjwt.Token) {
					_ = tok.Set(jwxjwt.IssuerKey, "attacker.example.com")
				})
			},
			wantStatusCode: http.StatusUnauthorized,
		},
		"no usable validator is denied": {
			authHeader:     func() string { return "Bearer " + signToken(t, signingKey, nil) },
			noValidators:   true,
			wantStatusCode: http.StatusUnauthorized,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := newTestOptions(t, verifyKeys, func(o *jwt.Options) {
				if tc.noValidators {
					o.SecurityTokenValidators = nil
				}
			})

			response := serve(t, opts, tc.authHeader(), protectedEndpoint())
			require.Equal(t, tc.wantStatusCode, response.Code)
		})
	}
}

// TestSaveBearerToken is contract H2: with SaveToken enabled, a successful
// authentication persists the raw bearer token under access_token in the
// authentication properties, and a downstream reader retrieves the same string.
func TestSaveBearerToken(t *testing.T) {
	t.Parallel()

	signingKey := newSigningKey(t, strings.Repeat("a", 128), testKid)
	opts := newTestOptions(t, keySet(t, signingKey), func(o *jwt.Options) {
		o.SaveToken = true
	})

	token := signToken(t, signingKey, nil)

	var retrieved string
	var retrieveErr error
	endpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := core.ResultFromContext(r.Context())
		if result == nil || !result.Succeeded() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		retrieved, retrieveErr = auth.GetTokenValue(result.Properties, "access_token")
		io.WriteString(w, retrieved)
	})

	response := serve(t, opts, "Bearer "+token, endpoint)

	require.Equal(t, http.StatusOK, response.Code)
	require.NoError(t, retrieveErr)
	require.NotEmpty(t, retrieved, "SaveToken must persist a non-empty token")
	require.Equal(t, token, retrieved, "retrieved token must match the presented bearer token byte-for-byte")
	require.Equal(t, token, response.Body.String())
}

// TestMiddlewareResultFromContext is contracts M1 and M2 at the middleware seam:
// a successful authentication places a succeeded result on the request context,
// while an unauthenticated request leaves the context result absent. M3 and M4
// from the source suite are not represented — they exercise a mutable
// user<->result feature that this immutable context-value face does not model.
func TestMiddlewareResultFromContext(t *testing.T) {
	t.Parallel()

	signingKey := newSigningKey(t, strings.Repeat("a", 128), testKid)
	verifyKeys := keySet(t, signingKey)

	tests := map[string]struct {
		authHeader    func() string
		wantResult    bool
		wantSucceeded bool
	}{
		"successful authentication sets a succeeded result": {
			authHeader:    func() string { return "Bearer " + signToken(t, signingKey, nil) },
			wantResult:    true,
			wantSucceeded: true,
		},
		"unauthenticated request leaves the result absent": {
			authHeader:    func() string { return "" },
			wantResult:    false,
			wantSucceeded: false,
		},
	}

	for name, tc := range tests {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := newTestOptions(t, verifyKeys, nil)

			var seen *auth.Result
			var seenSet bool
			downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = core.ResultFromContext(r.Context())
				seenSet = true
			})

			serve(t, opts, tc.authHeader(), downstream)

			require.True(t, seenSet, "middleware must always reach the downstream handler")
			if tc.wantResult {
				require.NotNil(t, seen, "successful authentication must expose a result on the context")
				require.Equal(t, tc.wantSucceeded, seen.Succeeded())
				require.NotNil(t, seen.Principal)
				require.Equal(t, testSubject, seen.Principal.FindFirst(claims.NameIdentifier).Value)
			} else {
				require.Nil(t, seen, "unauthenticated request must not place a result on the context")
			}
		})
	}
}
