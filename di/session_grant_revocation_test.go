// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/dp"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

func TestSetRevokeGrantsOnSessionSubjectChange(t *testing.T) {
	t.Parallel()

	cfg := NewServerConfig()
	if cfg.RevokeGrantsOnSessionSubjectChange() {
		t.Fatal("revocation is declared by default")
	}
	cfg.SetRevokeGrantsOnSessionSubjectChange(true)
	if !cfg.RevokeGrantsOnSessionSubjectChange() {
		t.Fatal("declared revocation is not reported")
	}
	cfg.SetRevokeGrantsOnSessionSubjectChange(false)
	if cfg.RevokeGrantsOnSessionSubjectChange() {
		t.Fatal("withdrawn revocation is still reported")
	}
	var nilConfig *ServerConfig
	if nilConfig.RevokeGrantsOnSessionSubjectChange() {
		t.Fatal("nil configuration reports revocation")
	}
}

func TestSetRevokeGrantsOnSessionSubjectChangePanicsAfterFreeze(t *testing.T) {
	_, cfg := newAssertionRoot(t)
	cfg.Freeze()
	text := panicText(t, func() { cfg.SetRevokeGrantsOnSessionSubjectChange(true) })
	if !strings.Contains(text, "SetRevokeGrantsOnSessionSubjectChange") || !strings.Contains(text, "after Freeze") {
		t.Fatalf("panic text %q", text)
	}
}

func TestSetSessionCookieDataProtectionProviderPanicsAfterFreeze(t *testing.T) {
	_, cfg := newAssertionRoot(t)
	cfg.Freeze()
	text := panicText(t, func() { cfg.SetSessionCookieDataProtectionProvider(&recordingDataProtectionProvider{}) })
	if !strings.Contains(text, "SetSessionCookieDataProtectionProvider") || !strings.Contains(text, "after Freeze") {
		t.Fatalf("panic text %q", text)
	}
}

// The resolved refresh token service records the session of the access
// token it is issued with only while revocation is declared.
func TestRefreshTokenServiceAssemblyRecordsTheSessionWhenRevoking(t *testing.T) {
	for name, revoke := range map[string]bool{"default": false, "declared": true} {
		t.Run(name, func(t *testing.T) {
			root, cfg := newAssertionRoot(t)
			if revoke {
				cfg.SetRevokeGrantsOnSessionSubjectChange(true)
				cfg.SetSessionCookieDataProtectionProvider(&recordingDataProtectionProvider{})
			}
			cfg.Freeze()

			client := storage_models.NewClient()
			client.ClientId = "client"
			service := godi.GetRequired[services.RefreshTokenService](root)
			handle, err := service.CreateRefreshToken(context.Background(), &responses_models.RefreshTokenCreationRequest{
				Client: client,
				AccessToken: &storage_models.Token{Claims: []*claims.Claim{
					claims.NewClaim(claims.WithClaimType(wicket.JwtClaimTypesSessionId), claims.WithClaimValue("session-1")),
				}},
			})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			token, err := godi.GetRequired[storage.RefreshTokenStore](root).GetRefreshToken(context.Background(), handle)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			want := ""
			if revoke {
				want = "session-1"
			}
			if token.SessionId != want {
				t.Fatalf("recorded session %q, want %q", token.SessionId, want)
			}
		})
	}
}

func TestFreezeRequiresTheSessionCookieDataProtectionWhileRevoking(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		revoke   bool
		provider dp.DataProtectionProvider
		panics   bool
	}{
		"revoking without a provider":           {revoke: true, panics: true},
		"revoking with the default provider":    {revoke: true, provider: services_impl.NewDataProtectionProvider(), panics: true},
		"the default provider without revoking": {provider: services_impl.NewDataProtectionProvider(), panics: true},
		"a nil default pointer":                 {provider: (*services_impl.DataProtectionProvider)(nil), panics: true},
		"revoking with a provider":              {revoke: true, provider: &recordingDataProtectionProvider{}},
		"neither":                               {},
		"a provider without revoking":           {provider: &recordingDataProtectionProvider{}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()
			cfg.SetRevokeGrantsOnSessionSubjectChange(tc.revoke)
			if tc.provider != nil {
				cfg.SetSessionCookieDataProtectionProvider(tc.provider)
			}
			if !tc.panics {
				cfg.Freeze()
				return
			}
			text := panicText(t, cfg.Freeze)
			if !strings.Contains(text, "SetSessionCookieDataProtectionProvider") {
				t.Fatalf("panic %q does not name SetSessionCookieDataProtectionProvider", text)
			}
		})
	}
}

// The composition root installs the revocation only together with a
// session cookie protector, also when Freeze was not called, and does not
// read the protection seam while the revocation is not declared.
func TestUserSessionAssemblyRequiresTheSessionCookieProtector(t *testing.T) {
	for name, provider := range map[string]dp.DataProtectionProvider{
		"no provider injected":      nil,
		"default provider":          services_impl.NewDataProtectionProvider(),
		"provider creating nothing": nilCreatingDataProtectionProvider{},
	} {
		t.Run(name, func(t *testing.T) {
			root, cfg := newAssertionRoot(t)
			cfg.SetRevokeGrantsOnSessionSubjectChange(true)
			if provider != nil {
				cfg.SetSessionCookieDataProtectionProvider(provider)
			}
			text := panicText(t, func() { godi.GetRequired[services.UserSession](root) })
			if !strings.Contains(text, `"session cookie data protection"`) {
				t.Fatalf("panic %q does not name the session cookie data protection seam", text)
			}
		})
	}
	for name, revoke := range map[string]bool{"declared": true, "not declared": false} {
		t.Run("provider read when "+name, func(t *testing.T) {
			root, cfg := newAssertionRoot(t)
			cfg.SetRevokeGrantsOnSessionSubjectChange(revoke)
			provider := &recordingDataProtectionProvider{}
			cfg.SetSessionCookieDataProtectionProvider(provider)
			cfg.Freeze()

			if godi.GetRequired[services.UserSession](root) == nil {
				t.Fatal("no user session")
			}
			var want []string
			if revoke {
				want = []string{SessionCookieProtectionPurpose}
			}
			if got := provider.created(); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("protectors created for %v, want %v", got, want)
			}
		})
	}
}
