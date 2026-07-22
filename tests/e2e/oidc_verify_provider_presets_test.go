// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket/oidcverify"
	"github.com/gonewx/wicket/test/common"
)

func TestOIDCVerifyGoogleDualIssuerE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuers:   []string{oidcverify.GoogleIssuerHTTPS, oidcverify.GoogleIssuerPlain},
		JWKSURI:   idp.srv.URL,
		Audiences: []string{oidcE2EAudience},
		ClockSkew: 5 * time.Minute,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tests := map[string]struct {
		issuer  string
		wantErr error
	}{
		"https issuer passes": {
			issuer: oidcverify.GoogleIssuerHTTPS,
		},
		"plain issuer passes": {
			issuer: oidcverify.GoogleIssuerPlain,
		},
		"spoofed issuer rejected": {
			issuer:  "https://accounts.google.com.evil.example.com",
			wantErr: oidcverify.ErrInvalidIssuer,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token := idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
				tok.Set(jwt.IssuerKey, tc.issuer)
			})

			result, err := v.Verify(context.Background(), token)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected rejection for issuer %q, got nil", tc.issuer)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify with issuer %q: %v", tc.issuer, err)
			}
			if result.Subject != oidcE2ESubject {
				t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
			}
			if result.Issuer != tc.issuer {
				t.Errorf("Issuer = %q, want %q", result.Issuer, tc.issuer)
			}
		})
	}
}

func TestOIDCVerifyMultiAudienceE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	const (
		webClientID = "123456789-abcdef.apps.googleusercontent.com"
		iosClientID = "com.example.ios"
	)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuers:   []string{oidcverify.GoogleIssuerHTTPS, oidcverify.GoogleIssuerPlain},
		JWKSURI:   idp.srv.URL,
		Audiences: []string{webClientID, iosClientID},
		ClockSkew: 5 * time.Minute,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tests := map[string]struct {
		aud     []string
		wantErr error
	}{
		"web client id matches": {
			aud: []string{webClientID},
		},
		"ios client id matches": {
			aud: []string{iosClientID},
		},
		"one of multiple token audiences matches": {
			aud: []string{"unknown-client", iosClientID},
		},
		"no intersection rejected": {
			aud:     []string{"com.attacker.app"},
			wantErr: oidcverify.ErrInvalidAudience,
		},
		"multiple non-matching rejected": {
			aud:     []string{"com.evil.one", "com.evil.two"},
			wantErr: oidcverify.ErrInvalidAudience,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token := idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
				tok.Set(jwt.IssuerKey, oidcverify.GoogleIssuerHTTPS)
				tok.Set(jwt.AudienceKey, tc.aud)
			})

			result, err := v.Verify(context.Background(), token)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected rejection for aud %v, got nil", tc.aud)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify with aud %v: %v", tc.aud, err)
			}
			if result.Subject != oidcE2ESubject {
				t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
			}
		})
	}
}

func TestOIDCVerifyAppleEmailToleranceE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	v, err := oidcverify.NewVerifier(context.Background(), oidcverify.ProviderConfig{
		Issuers:   []string{oidcverify.AppleIssuer},
		JWKSURI:   idp.srv.URL,
		Audiences: []string{oidcE2EAudience},
		ClockSkew: 5 * time.Minute,
	}, clock)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	tests := map[string]struct {
		mutate       func(jwt.Token)
		wantEmail    string
		wantVerified bool
	}{
		"email missing entirely": {
			mutate: func(tok jwt.Token) {
				tok.Set("email", nil)
				tok.Set("email_verified", nil)
			},
			wantEmail:    "",
			wantVerified: false,
		},
		"private relay email": {
			mutate: func(tok jwt.Token) {
				tok.Set("email", "a1b2c3@privaterelay.appleid.com")
				tok.Set("email_verified", true)
			},
			wantEmail:    "a1b2c3@privaterelay.appleid.com",
			wantVerified: true,
		},
		"email_verified as string true": {
			mutate: func(tok jwt.Token) {
				tok.Set("email", "user@example.com")
				tok.Set("email_verified", "true")
			},
			wantEmail:    "user@example.com",
			wantVerified: true,
		},
		"email_verified as string false": {
			mutate: func(tok jwt.Token) {
				tok.Set("email", "user@example.com")
				tok.Set("email_verified", "false")
			},
			wantEmail:    "user@example.com",
			wantVerified: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token := idp.issueIDToken(t, fixedNow, tc.mutate)

			result, err := v.Verify(context.Background(), token)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result.Subject != oidcE2ESubject {
				t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
			}
			if result.Email != tc.wantEmail {
				t.Errorf("Email = %q, want %q", result.Email, tc.wantEmail)
			}
			if result.EmailVerified != tc.wantVerified {
				t.Errorf("EmailVerified = %v, want %v", result.EmailVerified, tc.wantVerified)
			}
		})
	}
}

func TestOIDCVerifyAppleConfigPresetE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	cfg := oidcverify.AppleConfig(oidcE2EAudience)
	cfg.JWKSURI = idp.srv.URL

	v, err := oidcverify.NewVerifier(context.Background(), cfg, clock)
	if err != nil {
		t.Fatalf("NewVerifier with AppleConfig: %v", err)
	}

	token := idp.issueIDToken(t, fixedNow, nil)

	result, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Subject != oidcE2ESubject {
		t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
	}
	if result.Issuer != oidcverify.AppleIssuer {
		t.Errorf("Issuer = %q, want %q", result.Issuer, oidcverify.AppleIssuer)
	}
	if result.Email != oidcE2EEmail {
		t.Errorf("Email = %q, want %q", result.Email, oidcE2EEmail)
	}
}

func TestOIDCVerifyGoogleConfigPresetE2E(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	clock := common.NewMockSystemClock()
	clock.SetNow(fixedNow)

	idp := newOIDCE2EIdP(t)

	const (
		webClientID = "987654321-xyz.apps.googleusercontent.com"
		iosClientID = "com.example.ios.app"
	)

	cfg := oidcverify.GoogleConfig(webClientID, iosClientID)
	cfg.JWKSURI = idp.srv.URL

	v, err := oidcverify.NewVerifier(context.Background(), cfg, clock)
	if err != nil {
		t.Fatalf("NewVerifier with GoogleConfig: %v", err)
	}

	tests := map[string]struct {
		issuer  string
		aud     string
		wantErr error
	}{
		"https issuer + web client": {
			issuer: oidcverify.GoogleIssuerHTTPS,
			aud:    webClientID,
		},
		"plain issuer + ios client": {
			issuer: oidcverify.GoogleIssuerPlain,
			aud:    iosClientID,
		},
		"wrong audience rejected": {
			issuer:  oidcverify.GoogleIssuerHTTPS,
			aud:     "com.unknown.client",
			wantErr: oidcverify.ErrInvalidAudience,
		},
		"wrong issuer rejected": {
			issuer:  "https://login.microsoftonline.com",
			aud:     webClientID,
			wantErr: oidcverify.ErrInvalidIssuer,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token := idp.issueIDToken(t, fixedNow, func(tok jwt.Token) {
				tok.Set(jwt.IssuerKey, tc.issuer)
				tok.Set(jwt.AudienceKey, []string{tc.aud})
			})

			result, err := v.Verify(context.Background(), token)
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected rejection, got nil")
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if result.Subject != oidcE2ESubject {
				t.Errorf("Subject = %q, want %q", result.Subject, oidcE2ESubject)
			}
			if result.Issuer != tc.issuer {
				t.Errorf("Issuer = %q, want %q", result.Issuer, tc.issuer)
			}
		})
	}
}
