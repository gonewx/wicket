// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// TestHandlePromptNoneTurnsLoginIntoError covers the silent-failure surface: under
// prompt=none the top-level handler must convert every re-login requirement into a
// login_required error and must not signal an interactive login.
func TestHandlePromptNoneTurnsLoginIntoError(t *testing.T) {
	t.Parallel()

	now := time.Date(2020, 2, 3, 9, 0, 0, 0, time.UTC)

	cases := map[string]struct {
		setup func(*validators_models.ValidatedAuthorizeRequest)
	}{
		"restricted idp with local login disabled": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				c := storage_models.NewClient()
				c.EnableLocalLogin = false
				c.IdentityProviderRestrictions = []string{"some_idp"}
				r.Client = c
			},
		},
		"authentication older than max_age": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				authTime := time.Date(2020, 2, 1, 9, 0, 0, 0, time.UTC)
				r.Subject = localSubject(t, &authTime)
				r.Client = storage_models.NewClient()
				maxAge := 3600
				r.MaxAge = &maxAge
			},
		},
		"max_age zero forces a fresh authentication": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				// the subject authenticated an hour before now, yet max_age=0 rejects
				// any non-zero session age. the old int guard silently skipped this.
				authTime := now.Add(-1 * time.Hour)
				r.Subject = localSubject(t, &authTime)
				r.Client = storage_models.NewClient()
				maxAge := 0
				r.MaxAge = &maxAge
			},
		},
		"acr requests a different idp": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				r.Client = storage_models.NewClient()
				r.AuthenticationContextReferenceClasses = []string{gois.KnownAcrValuesHomeRealm + "some_idp"}
			},
		},
		"session beyond the client sso lifetime": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				authTime := now.Add(-3700 * time.Second)
				r.Subject = localSubject(t, &authTime)
				c := storage_models.NewClient()
				c.UserSsoLifetime = 3600
				r.Client = c
			},
		},
		"local session against a client that disables local login": {
			setup: func(r *validators_models.ValidatedAuthorizeRequest) {
				r.Subject = localSubject(t, nil)
				c := storage_models.NewClient()
				c.EnableLocalLogin = false
				r.Client = c
			},
		},
	}

	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := validators_models.NewValidatedAuthorizeRequest()
			req.PromptModes = []string{gois.PromptModesNone}
			tc.setup(req)
			g := buildGenerator(fixedClock(now), common.NewMockConsentService(), common.NewMockProfileService())

			resp := g.Handle(context.Background(), req, nil)

			if !errors.Is(resp.Error, gois.AuthorizeErrorsLoginRequired) {
				t.Fatalf("Error = %v, want login_required", resp.Error)
			}
			if resp.IsLogin {
				t.Fatalf("IsLogin = true, want false under prompt=none")
			}
		})
	}
}
