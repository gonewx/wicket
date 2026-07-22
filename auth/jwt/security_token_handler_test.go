// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	authjwt "github.com/gonewx/wicket/auth/jwt"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/test/common"
)

func fixedKey(t *testing.T) jwk.Key {
	t.Helper()
	key, err := jwk.Import([]byte(strings.Repeat("k", 128)))
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "unit-key"))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.HS256()))
	return key
}

func fixedKeySet(t *testing.T, key jwk.Key) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))
	return set
}

func issueToken(t *testing.T, key jwk.Key, mutate func(jwxjwt.Token)) string {
	t.Helper()
	tok := jwxjwt.New()
	require.NoError(t, tok.Set(jwxjwt.IssuerKey, "test-issuer"))
	require.NoError(t, tok.Set(jwxjwt.AudienceKey, "test-audience"))
	require.NoError(t, tok.Set(jwxjwt.SubjectKey, "user-1"))
	require.NoError(t, tok.Set(jwxjwt.ExpirationKey, time.Now().Add(30*time.Minute)))
	require.NoError(t, tok.Set(jwxjwt.NotBeforeKey, time.Now().Add(-1*time.Minute)))
	if mutate != nil {
		mutate(tok)
	}
	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.HS256(), key))
	require.NoError(t, err)
	return string(signed)
}

func baseParams(t *testing.T, key jwk.Key) *authjwt.TokenValidationParameters {
	t.Helper()
	return &authjwt.TokenValidationParameters{
		ValidIssuer:         "test-issuer",
		ValidAudience:       "test-audience",
		Keys:                fixedKeySet(t, key),
		RequireSignedTokens: true,
		ValidateLifetime:    true,
	}
}

// TestCanReadToken verifies the structural token detection without validation.
func TestCanReadToken(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	tests := map[string]struct {
		token string
		want  bool
	}{
		"valid JWT is readable": {
			token: issueToken(t, key, nil),
			want:  true,
		},
		"garbage string is not readable": {
			token: "not-a-jwt",
			want:  false,
		},
		"empty string is not readable": {
			token: "",
			want:  false,
		},
		"two-segment string is not readable": {
			token: "header.payload",
			want:  false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, handler.CanReadToken(tc.token))
		})
	}
}

// TestValidateLifetimeFalse covers the 6-4 defer fix: with ValidateLifetime
// disabled, expired tokens pass while issuer/audience checks remain enforced.
func TestValidateLifetimeFalse(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	tests := map[string]struct {
		token   string
		params  func() *authjwt.TokenValidationParameters
		wantErr bool
	}{
		"expired token passes when lifetime validation is disabled": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.ExpirationKey, time.Now().Add(-10*time.Minute))
			}),
			params: func() *authjwt.TokenValidationParameters {
				p := baseParams(t, key)
				p.ValidateLifetime = false
				return p
			},
			wantErr: false,
		},
		"not-yet-valid token passes when lifetime validation is disabled": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.NotBeforeKey, time.Now().Add(10*time.Minute))
			}),
			params: func() *authjwt.TokenValidationParameters {
				p := baseParams(t, key)
				p.ValidateLifetime = false
				return p
			},
			wantErr: false,
		},
		"issuer mismatch is still rejected": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.IssuerKey, "wrong-issuer")
			}),
			params: func() *authjwt.TokenValidationParameters {
				p := baseParams(t, key)
				p.ValidateLifetime = false
				return p
			},
			wantErr: true,
		},
		"audience mismatch is still rejected": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.AudienceKey, "wrong-audience")
			}),
			params: func() *authjwt.TokenValidationParameters {
				p := baseParams(t, key)
				p.ValidateLifetime = false
				return p
			},
			wantErr: true,
		},
		"valid token passes normally": {
			token: issueToken(t, key, nil),
			params: func() *authjwt.TokenValidationParameters {
				p := baseParams(t, key)
				p.ValidateLifetime = false
				return p
			},
			wantErr: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := handler.ValidateToken(tc.token, tc.params())
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestValidateLifetimeTrue confirms the standard temporal enforcement.
func TestValidateLifetimeTrue(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	tests := map[string]struct {
		token   string
		wantErr bool
	}{
		"valid token passes": {
			token:   issueToken(t, key, nil),
			wantErr: false,
		},
		"expired token is rejected": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.ExpirationKey, time.Now().Add(-10*time.Minute))
			}),
			wantErr: true,
		},
		"not-yet-valid token is rejected": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.NotBeforeKey, time.Now().Add(10*time.Minute))
			}),
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := handler.ValidateToken(tc.token, baseParams(t, key))
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestClockInjection verifies that the injected clock is honored in both
// lifetime-enabled and lifetime-disabled branches (6-4 fix: clock was
// previously discarded in the ValidateLifetime=false path).
func TestClockInjection(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	fixedNow := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		token        string
		validateLife bool
		clockNow     time.Time
		wantErr      bool
	}{
		"clock set before expiry passes with lifetime enabled": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.ExpirationKey, fixedNow.Add(5*time.Minute))
				_ = tok.Set(jwxjwt.NotBeforeKey, fixedNow.Add(-5*time.Minute))
			}),
			validateLife: true,
			clockNow:     fixedNow,
			wantErr:      false,
		},
		"clock set after expiry fails with lifetime enabled": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.ExpirationKey, fixedNow.Add(-1*time.Minute))
				_ = tok.Set(jwxjwt.NotBeforeKey, fixedNow.Add(-10*time.Minute))
			}),
			validateLife: true,
			clockNow:     fixedNow,
			wantErr:      true,
		},
		"clock set after expiry passes with lifetime disabled": {
			token: issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.ExpirationKey, fixedNow.Add(-1*time.Minute))
				_ = tok.Set(jwxjwt.NotBeforeKey, fixedNow.Add(-10*time.Minute))
			}),
			validateLife: false,
			clockNow:     fixedNow,
			wantErr:      false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			clock := common.NewMockSystemClock()
			clock.SetNow(tc.clockNow)

			params := baseParams(t, key)
			params.ValidateLifetime = tc.validateLife
			params.Clock = clock

			_, _, err := handler.ValidateToken(tc.token, params)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestClockSkew verifies the tolerance window absorbs small clock differences.
func TestClockSkew(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	now := time.Now()

	tests := map[string]struct {
		expOffset time.Duration
		skew      time.Duration
		wantErr   bool
	}{
		"expired within skew passes": {
			expOffset: -2 * time.Minute,
			skew:      5 * time.Minute,
			wantErr:   false,
		},
		"expired beyond skew fails": {
			expOffset: -10 * time.Minute,
			skew:      5 * time.Minute,
			wantErr:   true,
		},
		"zero skew with expired token fails": {
			expOffset: -1 * time.Minute,
			skew:      0,
			wantErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			token := issueToken(t, key, func(tok jwxjwt.Token) {
				_ = tok.Set(jwxjwt.ExpirationKey, now.Add(tc.expOffset))
				_ = tok.Set(jwxjwt.NotBeforeKey, now.Add(-1*time.Hour))
			})

			params := baseParams(t, key)
			params.ClockSkew = tc.skew

			_, _, err := handler.ValidateToken(token, params)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestPrincipalClaimProjection verifies that private claims are projected onto
// the ClaimsPrincipal and standard claims are mapped to their canonical types.
func TestPrincipalClaimProjection(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	token := issueToken(t, key, func(tok jwxjwt.Token) {
		_ = tok.Set("custom_role", "admin")
		_ = tok.Set("custom_scope", "read write")
		_ = tok.Set(jwxjwt.JwtIDKey, "jti-123")
	})

	principal, _, err := handler.ValidateToken(token, baseParams(t, key))
	require.NoError(t, err)
	require.NotNil(t, principal)

	identity := principal.Identity()
	require.NotNil(t, identity)
	require.True(t, identity.IsAuthenticated())

	require.Equal(t, "test-issuer", principal.FindFirst("iss").Value)
	require.Equal(t, "user-1", principal.FindFirst(claims.NameIdentifier).Value)
	require.Equal(t, "jti-123", principal.FindFirst("jti").Value)
	require.Equal(t, "test-audience", principal.FindFirst("aud").Value)
	require.Equal(t, "admin", principal.FindFirst("custom_role").Value)
	require.Equal(t, "read write", principal.FindFirst("custom_scope").Value)
}

// TestSecurityTokenTemporalBounds verifies that the returned SecurityToken
// exposes the correct ValidTo/ValidFrom from the token's exp/nbf claims.
func TestSecurityTokenTemporalBounds(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	exp := time.Now().Add(1 * time.Hour).Truncate(time.Second)
	nbf := time.Now().Add(-5 * time.Minute).Truncate(time.Second)

	token := issueToken(t, key, func(tok jwxjwt.Token) {
		_ = tok.Set(jwxjwt.ExpirationKey, exp)
		_ = tok.Set(jwxjwt.NotBeforeKey, nbf)
	})

	_, secToken, err := handler.ValidateToken(token, baseParams(t, key))
	require.NoError(t, err)
	require.NotNil(t, secToken)

	require.True(t, secToken.ValidTo().Equal(exp),
		"ValidTo = %v, want %v", secToken.ValidTo(), exp)
	require.True(t, secToken.ValidFrom().Equal(nbf),
		"ValidFrom = %v, want %v", secToken.ValidFrom(), nbf)
}

// TestUnsignedTokenValidation verifies that RequireSignedTokens=false allows
// parsing without signature verification.
func TestUnsignedTokenValidation(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	token := issueToken(t, key, nil)

	params := baseParams(t, key)
	params.RequireSignedTokens = false
	params.Keys = nil

	principal, _, err := handler.ValidateToken(token, params)
	require.NoError(t, err)
	require.NotNil(t, principal)
	require.Equal(t, "user-1", principal.FindFirst(claims.NameIdentifier).Value)
}

// TestNilParametersDefaults verifies that nil parameters fall back to safe
// defaults (signed tokens required, lifetime validated).
func TestNilParametersDefaults(t *testing.T) {
	t.Parallel()

	key := fixedKey(t)
	handler := authjwt.NewSecurityTokenHandler()

	token := issueToken(t, key, nil)

	_, _, err := handler.ValidateToken(token, nil)
	require.Error(t, err, "nil params defaults to RequireSignedTokens=true with no keys, so validation must fail")
}
