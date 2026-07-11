// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"net/url"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// TestHandleLoginDecision drives the login-necessity decision across the session
// and client conditions the generator evaluates. The clock is pinned so the two
// session-age conditions (max_age is exercised through Handle in the top-level
// suite; the client SSO lifetime here) compare against a known instant.
func TestHandleLoginDecision(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	restrictedClient := func() *storage_models.Client {
		c := storage_models.NewClient()
		c.EnableLocalLogin = false
		c.IdentityProviderRestrictions = []string{"some_idp"}
		return c
	}

	cases := map[string]struct {
		setup     func(*validators_models.ValidatedAuthorizeRequest)
		wantLogin bool
	}{
		"anonymous subject must authenticate": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = claims.ClaimsPrincipalAnonymous()
			},
			wantLogin: true,
		},
		"authenticated local session with a plain client passes": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				r.Client = storage_models.NewClient()
			},
			wantLogin: false,
		},
		"current idp inside the client allow list passes": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				c := storage_models.NewClient()
				c.IdentityProviderRestrictions = []string{gois.LocalIdentityProvider}
				r.Client = c
			},
			wantLogin: false,
		},
		"current idp outside the client allow list forces login": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				r.Client = restrictedClient()
			},
			wantLogin: true,
		},
		"acr requests the current idp and passes": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				r.Client = storage_models.NewClient()
				r.AuthenticationContextReferenceClasses = []string{gois.KnownAcrValuesHomeRealm + gois.LocalIdentityProvider}
			},
			wantLogin: false,
		},
		"acr requests a different idp and forces login": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				r.Client = storage_models.NewClient()
				r.AuthenticationContextReferenceClasses = []string{gois.KnownAcrValuesHomeRealm + "some_idp"}
			},
			wantLogin: true,
		},
		"session within the client sso lifetime passes": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				authTime := now.Add(-10 * time.Second)
				r.Subject = localSubject(t, &authTime)
				c := storage_models.NewClient()
				c.UserSsoLifetime = 3600
				r.Client = c
			},
			wantLogin: false,
		},
		"session beyond the client sso lifetime forces login": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				authTime := now.Add(-3700 * time.Second)
				r.Subject = localSubject(t, &authTime)
				c := storage_models.NewClient()
				c.UserSsoLifetime = 3600
				r.Client = c
			},
			wantLogin: true,
		},
		"local session against a client that disables local login forces login": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				c := storage_models.NewClient()
				c.EnableLocalLogin = false
				r.Client = c
			},
			wantLogin: true,
		},
		"prompt=login forces login without touching the client": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				r.Raw = url.Values{}
				r.PromptModes = []string{gois.PromptModesLogin}
			},
			wantLogin: true,
		},
		"prompt=select_account forces login without touching the client": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				r.Raw = url.Values{}
				r.PromptModes = []string{gois.PromptModesSelectAccount}
			},
			wantLogin: true,
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := validators_models.NewValidatedAuthorizeRequest()
			tc.setup(req)
			g := buildGenerator(fixedClock(now), common.NewMockConsentService(), common.NewMockProfileService())

			resp := g.HandleLogin(req)

			if resp.IsLogin != tc.wantLogin {
				t.Fatalf("IsLogin = %v, want %v", resp.IsLogin, tc.wantLogin)
			}
		})
	}
}

// TestHandleLoginSuppressesPromptOnForcedLogin covers the suppression side effect:
// once a login prompt has forced re-authentication, the original prompt is removed
// from the raw parameters and a suppression marker is written so the follow-up
// request does not loop back into the same forced login.
func TestHandleLoginSuppressesPromptOnForcedLogin(t *testing.T) {
	t.Parallel()

	req := validators_models.NewValidatedAuthorizeRequest()
	req.Subject = localSubject(t, nil)
	req.PromptModes = []string{gois.PromptModesLogin}
	req.Raw = url.Values{gois.AuthorizeRequestPrompt: {gois.PromptModesLogin}}

	g := buildGenerator(fixedClock(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)), common.NewMockConsentService(), common.NewMockProfileService())

	resp := g.HandleLogin(req)

	if !resp.IsLogin {
		t.Fatalf("IsLogin = false, want true for prompt=login")
	}
	if !req.Raw.Has(gois.SuppressedPrompt) {
		t.Fatalf("expected the raw parameters to carry the %q suppression marker, got %v", gois.SuppressedPrompt, req.Raw)
	}
}
