// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	"github.com/gonewx/wicket/oidcverify"
	"github.com/gonewx/wicket/test/common"
)

const (
	oidcE2EIssuer   = "https://appleid.apple.com"
	oidcE2EAudience = "com.example.meetup"
	oidcE2ESubject  = "001234.abcdef.5678"
	oidcE2EEmail    = "user@privaterelay.appleid.com"
)

type oidcE2EIdP struct {
	privKey *rsa.PrivateKey
	kid     string
	mu      sync.Mutex
	set     jwk.Set
	srv     *httptest.Server
}

func newOIDCE2EIdP(t *testing.T) *oidcE2EIdP {
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

	idp := &oidcE2EIdP{
		privKey: priv,
		kid:     kid,
		set:     set,
	}

	idp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		s := idp.set
		idp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		buf, err := json.Marshal(s)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(buf)
	}))
	t.Cleanup(idp.srv.Close)

	return idp
}

func (idp *oidcE2EIdP) rotateKey(t *testing.T) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rotated RSA key: %v", err)
	}

	pub := &priv.PublicKey
	key, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("import rotated public key: %v", err)
	}
	if err := jwk.AssignKeyID(key); err != nil {
		t.Fatalf("assign rotated key ID: %v", err)
	}
	kid, _ := key.KeyID()

	newSet := jwk.NewSet()
	if err := newSet.AddKey(key); err != nil {
		t.Fatalf("add rotated key to set: %v", err)
	}

	idp.mu.Lock()
	idp.privKey = priv
	idp.kid = kid
	idp.set = newSet
	idp.mu.Unlock()
}

func (idp *oidcE2EIdP) issueIDToken(t *testing.T, now time.Time, mutate func(jwt.Token)) string {
	t.Helper()

	tok := jwt.New()
	tok.Set(jwt.SubjectKey, oidcE2ESubject)
	tok.Set(jwt.IssuerKey, oidcE2EIssuer)
	tok.Set(jwt.AudienceKey, []string{oidcE2EAudience})
	tok.Set(jwt.ExpirationKey, now.Add(time.Hour))
	tok.Set(jwt.IssuedAtKey, now.Add(-time.Minute))
	tok.Set("email", oidcE2EEmail)
	tok.Set("email_verified", true)
	tok.Set("auth_time", now.Add(-2*time.Minute).Unix())

	if mutate != nil {
		mutate(tok)
	}

	idp.mu.Lock()
	priv := idp.privKey
	kid := idp.kid
	idp.mu.Unlock()

	key, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	key.Set(jwk.KeyIDKey, kid)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return string(signed)
}

func TestOIDCVerifyExternalIdPTokenFlowE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 14, 30, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuer:    oidcE2EIssuer,
		JWKSURI:   idp.srv.URL,
		Audience:  oidcE2EAudience,
		ClockSkew: 5 * time.Minute,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	idToken := idp.issueIDToken(t, fixedNow, nil)

	result, err := v.Verify(context.Background(), idToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if result.Subject != oidcE2ESubject {
		t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
	}
	if result.Email != oidcE2EEmail {
		t.Errorf("Email = %q, want %q", result.Email, oidcE2EEmail)
	}
	if !result.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}
	if result.Issuer != oidcE2EIssuer {
		t.Errorf("Issuer = %q, want %q", result.Issuer, oidcE2EIssuer)
	}
	if len(result.Audience) != 1 || result.Audience[0] != oidcE2EAudience {
		t.Errorf("Audience = %v, want [%q]", result.Audience, oidcE2EAudience)
	}
}

func TestOIDCVerifyKeyRotationE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 14, 30, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuer:   oidcE2EIssuer,
		JWKSURI:  idp.srv.URL,
		Audience: oidcE2EAudience,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	firstToken := idp.issueIDToken(t, fixedNow, nil)
	result, err := v.Verify(context.Background(), firstToken)
	if err != nil {
		t.Fatalf("Verify before rotation: %v", err)
	}
	if result.Subject != oidcE2ESubject {
		t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
	}

	idp.rotateKey(t)

	rotatedToken := idp.issueIDToken(t, fixedNow, nil)
	result, err = v.Verify(context.Background(), rotatedToken)
	if err != nil {
		t.Fatalf("Verify after rotation (kid refresh fallback): %v", err)
	}
	if result.Subject != oidcE2ESubject {
		t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
	}
}

func TestOIDCVerifyTokenLifecycleE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 14, 30, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuer:    oidcE2EIssuer,
		JWKSURI:   idp.srv.URL,
		Audience:  oidcE2EAudience,
		ClockSkew: 5 * time.Minute,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	shortLivedToken := idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
		tok.Set(jwt.ExpirationKey, fixedNow.Add(10*time.Minute))
	})

	result, err := v.Verify(context.Background(), shortLivedToken)
	if err != nil {
		t.Fatalf("Verify within validity window: %v", err)
	}
	if result.Subject != oidcE2ESubject {
		t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
	}

	clock.SetNow(fixedNow.Add(16 * time.Minute))
	_, err = v.Verify(context.Background(), shortLivedToken)
	if err == nil {
		t.Fatal("expected token to be expired after clock advance")
	}
	if !errors.Is(err, oidcverify.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestOIDCVerifyNonceFlowE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 14, 30, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuer:        oidcE2EIssuer,
		JWKSURI:       idp.srv.URL,
		Audience:      oidcE2EAudience,
		NonceRequired: true,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	const expectedNonce = "n-0S6_WzA2Mj"

	tokenWithNonce := idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
		tok.Set("nonce", expectedNonce)
	})

	result, err := v.VerifyWithNonce(context.Background(), tokenWithNonce, expectedNonce)
	if err != nil {
		t.Fatalf("VerifyWithNonce: %v", err)
	}
	if result.Subject != oidcE2ESubject {
		t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
	}

	tokenNoNonce := idp.issueIDToken(t, fixedNow, nil)
	_, err = v.Verify(context.Background(), tokenNoNonce)
	if err == nil {
		t.Fatal("expected error when nonce required but missing")
	}
	if !errors.Is(err, oidcverify.ErrMissingNonce) {
		t.Fatalf("expected ErrMissingNonce, got: %v", err)
	}

	_, err = v.VerifyWithNonce(context.Background(), tokenWithNonce, "wrong-nonce")
	if err == nil {
		t.Fatal("expected error for nonce mismatch")
	}
	if !errors.Is(err, oidcverify.ErrInvalidNonce) {
		t.Fatalf("expected ErrInvalidNonce, got: %v", err)
	}
}

func TestOIDCVerifyAttackRejectionE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 14, 30, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuer:   oidcE2EIssuer,
		JWKSURI:  idp.srv.URL,
		Audience: oidcE2EAudience,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tests := map[string]struct {
		token   string
		wantErr error
	}{
		"issuer spoofing": {
			token: idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
				tok.Set(jwt.IssuerKey, "https://evil-idp.example.com")
			}),
			wantErr: oidcverify.ErrInvalidIssuer,
		},
		"audience mismatch": {
			token: idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
				tok.Set(jwt.AudienceKey, []string{"com.attacker.app"})
			}),
			wantErr: oidcverify.ErrInvalidAudience,
		},
		"expired token replay": {
			token: idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
				tok.Set(jwt.ExpirationKey, fixedNow.Add(-2*time.Hour))
				tok.Set(jwt.IssuedAtKey, fixedNow.Add(-3*time.Hour))
			}),
			wantErr: oidcverify.ErrTokenExpired,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := v.Verify(context.Background(), tc.token)
			if err == nil {
				t.Fatalf("expected rejection for %s, got nil", name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestOIDCVerifyEmailVerifiedStringVariantE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 14, 30, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuer:   oidcE2EIssuer,
		JWKSURI:  idp.srv.URL,
		Audience: oidcE2EAudience,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tests := map[string]struct {
		emailVerified any
		want          bool
	}{
		"boolean true":  {emailVerified: true, want: true},
		"boolean false": {emailVerified: false, want: false},
		"string true":   {emailVerified: "true", want: true},
		"string false":  {emailVerified: "false", want: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token := idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
				tok.Set("email_verified", tc.emailVerified)
			})

			result, err := v.Verify(context.Background(), token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result.EmailVerified != tc.want {
				t.Errorf("EmailVerified = %v, want %v", result.EmailVerified, tc.want)
			}
		})
	}
}
