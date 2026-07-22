// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package oidcverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket/test/common"
)

const (
	testIssuer   = "https://issuer.example.com"
	testAudience = "test-audience"
	testSubject  = "user-123"
	testEmail    = "user@example.com"
)

type testEnv struct {
	privKey  *rsa.PrivateKey
	kid      string
	jwksSrv  *httptest.Server
	clock    *common.MockSystemClock
	fixedNow time.Time
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	pub := &priv.PublicKey
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("import public key: %v", err)
	}
	if err := jwk.AssignKeyID(key); err != nil {
		t.Fatalf("assign key ID: %v", err)
	}
	kid, _ := key.KeyID()

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatalf("add key to set: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		buf, err := json.Marshal(set)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(buf)
	}))
	t.Cleanup(srv.Close)

	fixedNow := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	return &testEnv{
		privKey:  priv,
		kid:      kid,
		jwksSrv:  srv,
		clock:    clock,
		fixedNow: fixedNow,
	}
}

func (e *testEnv) newVerifier(t *testing.T, cfg ProviderConfig) Verifier {
	t.Helper()
	if cfg.Issuer == "" {
		cfg.Issuer = testIssuer
	}
	if cfg.JWKSURI == "" {
		cfg.JWKSURI = e.jwksSrv.URL
	}
	if cfg.Audience == "" {
		cfg.Audience = testAudience
	}
	v, err := NewVerifier(context.Background(), cfg, e.clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func (e *testEnv) signToken(t *testing.T, mutate func(jwt.Token)) string {
	t.Helper()
	return e.signTokenWithKid(t, e.kid, mutate)
}

func (e *testEnv) signTokenWithKid(t *testing.T, kid string, mutate func(jwt.Token)) string {
	t.Helper()

	tok := jwt.New()
	tok.Set(jwt.SubjectKey, testSubject)
	tok.Set(jwt.IssuerKey, testIssuer)
	tok.Set(jwt.AudienceKey, []string{testAudience})
	tok.Set(jwt.ExpirationKey, e.fixedNow.Add(time.Hour))
	tok.Set(jwt.IssuedAtKey, e.fixedNow.Add(-time.Minute))
	tok.Set("email", testEmail)
	tok.Set("email_verified", true)

	if mutate != nil {
		mutate(tok)
	}

	key, err := jwk.Import(e.privKey)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	key.Set(jwk.KeyIDKey, kid)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

func TestVerify(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{})

	validToken := env.signToken(t, nil)

	tests := map[string]struct {
		token   string
		wantErr error
		wantSub string
	}{
		"valid token": {
			token:   validToken,
			wantSub: testSubject,
		},
		"expired token": {
			token: env.signToken(t, func(tok jwt.Token) {
				tok.Set(jwt.ExpirationKey, env.fixedNow.Add(-time.Hour))
			}),
			wantErr: ErrTokenExpired,
		},
		"wrong audience": {
			token: env.signToken(t, func(tok jwt.Token) {
				tok.Set(jwt.AudienceKey, []string{"wrong-audience"})
			}),
			wantErr: ErrInvalidAudience,
		},
		"wrong issuer": {
			token: env.signToken(t, func(tok jwt.Token) {
				tok.Set(jwt.IssuerKey, "https://evil.example.com")
			}),
			wantErr: ErrInvalidIssuer,
		},
		"tampered signature": {
			token: func() string {
				tok := env.signToken(t, nil)
				raw := []byte(tok)
				lastDot := len(raw) - 5
				if raw[lastDot] == 'A' {
					raw[lastDot] = 'B'
				} else {
					raw[lastDot] = 'A'
				}
				return string(raw)
			}(),
			wantErr: ErrInvalidSignature,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := v.Verify(context.Background(), tc.token)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error wrapping %v, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Subject != tc.wantSub {
				t.Errorf("Subject = %q, want %q", result.Subject, tc.wantSub)
			}
		})
	}
}

func TestVerifyValidTokenFields(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{})

	token := env.signToken(t, nil)
	result, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Subject != testSubject {
		t.Errorf("Subject = %q, want %q", result.Subject, testSubject)
	}
	if result.Email != testEmail {
		t.Errorf("Email = %q, want %q", result.Email, testEmail)
	}
	if !result.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}
	if result.Issuer != testIssuer {
		t.Errorf("Issuer = %q, want %q", result.Issuer, testIssuer)
	}
	if len(result.Audience) != 1 || result.Audience[0] != testAudience {
		t.Errorf("Audience = %v, want [%q]", result.Audience, testAudience)
	}
}

func TestVerifyWrongKid(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{})

	token := env.signTokenWithKid(t, "nonexistent-kid", nil)

	_, err := v.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for wrong kid, got nil")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestVerifyAlgNone(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{})

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-123","iss":"https://issuer.example.com","aud":["test-audience"],"exp":9999999999}`))
	unsignedToken := header + "." + payload + "."

	_, err := v.Verify(context.Background(), unsignedToken)
	if err == nil {
		t.Fatal("expected error for alg=none, got nil")
	}
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Fatalf("expected ErrInvalidAlgorithm, got: %v", err)
	}
}

func TestVerifyHS256Downgrade(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{})

	tok := jwt.New()
	tok.Set(jwt.SubjectKey, testSubject)
	tok.Set(jwt.IssuerKey, testIssuer)
	tok.Set(jwt.AudienceKey, []string{testAudience})
	tok.Set(jwt.ExpirationKey, env.fixedNow.Add(time.Hour))
	tok.Set(jwt.IssuedAtKey, env.fixedNow)

	key, err := jwk.Import([]byte("super-secret-hmac-key-that-is-long-enough"))
	if err != nil {
		t.Fatalf("import HMAC key: %v", err)
	}
	key.Set(jwk.KeyIDKey, env.kid)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("sign with HS256: %v", err)
	}

	_, err = v.Verify(context.Background(), string(signed))
	if err == nil {
		t.Fatal("expected error for HS256 downgrade, got nil")
	}
	if !errors.Is(err, ErrInvalidAlgorithm) {
		t.Fatalf("expected ErrInvalidAlgorithm, got: %v", err)
	}
}

func TestVerifyNonceRequired(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{NonceRequired: true})

	tokenNoNonce := env.signToken(t, nil)
	_, err := v.Verify(context.Background(), tokenNoNonce)
	if err == nil {
		t.Fatal("expected error for missing nonce, got nil")
	}
	if !errors.Is(err, ErrMissingNonce) {
		t.Fatalf("expected ErrMissingNonce, got: %v", err)
	}
}

func TestVerifyWithNonce(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{})

	tokenWithNonce := env.signToken(t, func(tok jwt.Token) {
		tok.Set("nonce", "expected-nonce-123")
	})

	result, err := v.VerifyWithNonce(context.Background(), tokenWithNonce, "expected-nonce-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Subject != testSubject {
		t.Errorf("Subject = %q, want %q", result.Subject, testSubject)
	}

	_, err = v.VerifyWithNonce(context.Background(), tokenWithNonce, "wrong-nonce")
	if err == nil {
		t.Fatal("expected error for wrong nonce, got nil")
	}
	if !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("expected ErrInvalidNonce, got: %v", err)
	}
}

func TestVerifyClockInjection(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	v := env.newVerifier(t, ProviderConfig{ClockSkew: 0})

	token := env.signToken(t, func(tok jwt.Token) {
		tok.Set(jwt.ExpirationKey, env.fixedNow.Add(30*time.Second))
		tok.Set(jwt.IssuedAtKey, env.fixedNow.Add(-time.Minute))
	})

	result, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("token should be valid at fixed time: %v", err)
	}
	if result.Subject != testSubject {
		t.Errorf("Subject = %q, want %q", result.Subject, testSubject)
	}

	env.clock.SetNow(env.fixedNow.Add(time.Hour))
	_, err = v.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("token should be expired after clock advance")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired after clock advance, got: %v", err)
	}
}

func TestVerifyKidRefreshFallback(t *testing.T) {
	t.Parallel()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	pub := &priv.PublicKey
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("import public key: %v", err)
	}
	jwk.AssignKeyID(key)
	kid, _ := key.KeyID()

	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate other RSA key: %v", err)
	}
	otherPub := &otherPriv.PublicKey
	otherKey, err := jwk.Import(otherPub)
	if err != nil {
		t.Fatalf("import other public key: %v", err)
	}
	jwk.AssignKeyID(otherKey)

	initialSet := jwk.NewSet()
	initialSet.AddKey(otherKey)

	updatedSet := jwk.NewSet()
	updatedSet.AddKey(key)

	var mu sync.Mutex
	currentSet := initialSet
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s := currentSet
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		buf, _ := json.Marshal(s)
		w.Write(buf)
	}))
	t.Cleanup(srv.Close)

	fixedNow := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	v, err := NewVerifier(context.Background(), ProviderConfig{
		Issuer:   testIssuer,
		JWKSURI:  srv.URL,
		Audience: testAudience,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tok := jwt.New()
	tok.Set(jwt.SubjectKey, testSubject)
	tok.Set(jwt.IssuerKey, testIssuer)
	tok.Set(jwt.AudienceKey, []string{testAudience})
	tok.Set(jwt.ExpirationKey, fixedNow.Add(time.Hour))
	tok.Set(jwt.IssuedAtKey, fixedNow)

	privJwk, _ := jwk.Import(priv)
	privJwk.Set(jwk.KeyIDKey, kid)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), privJwk))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	mu.Lock()
	currentSet = updatedSet
	mu.Unlock()

	result, err := v.Verify(context.Background(), string(signed))
	if err != nil {
		t.Fatalf("expected success after kid refresh fallback, got: %v", err)
	}
	if result.Subject != testSubject {
		t.Errorf("Subject = %q, want %q", result.Subject, testSubject)
	}
}
