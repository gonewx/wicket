// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// fixedInteractionTime is the reference instant injected through the clock
// seam for every session-lifetime evaluation in this package's tests.
var fixedInteractionTime = time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)

func newFixedStubClock() *test_common.StubClock {
	clock := test_common.NewStubClock()
	clock.NowFunc = func() time.Time { return fixedInteractionTime }
	return clock
}

func newInteractionResponseGenerator(clock services.SystemClock) *AuthorizeInteractionResponseGenerator {
	return NewAuthorizeInteractionResponseGenerator(
		test_common.NewTestLogger(),
		clock,
		config_options.NewWicketOptions(),
		services_impl.NewConsentService(),
		test_common.NewMockProfileService(),
		services_impl.NewServerUrlsFromAccessor(nil),
		test_common.NewQueryStringAuthorizationParametersMessageStore(),
	)
}

// newSignedInLocalSubject builds a principal authenticated through the local
// identity provider, optionally carrying an authentication-time claim.
func newSignedInLocalSubject(t *testing.T, authTime *time.Time) *claimspkg.ClaimsPrincipal {
	t.Helper()

	user := models.NewLocalUser(models.WithLocalUserSubjectId("123"))
	user.IdentityProvider = gois.LocalIdentityProvider
	user.AuthenticationTime = authTime

	subject, err := user.CreatePrincipal()
	require.NoError(t, err)

	return subject
}

func TestHandleLogin_SessionEvaluation(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		arrange   func(t *testing.T) *validators_models.ValidatedAuthorizeRequest
		wantLogin bool
	}{
		"anonymous subject must sign in": {
			arrange: func(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
				req := validators_models.NewValidatedAuthorizeRequest()
				req.Subject = claimspkg.ClaimsPrincipalAnonymous()
				req.Client = storage_models.NewClient()
				return req
			},
			wantLogin: true,
		},
		"current identity provider excluded by client restrictions": {
			arrange: func(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
				req := validators_models.NewValidatedAuthorizeRequest()
				req.Subject = newSignedInLocalSubject(t, nil)
				req.Client = storage_models.NewClient()
				req.Client.EnableLocalLogin = false
				req.Client.IdentityProviderRestrictions = []string{"some_idp"}
				return req
			},
			wantLogin: true,
		},
		"acr requests a different identity provider": {
			arrange: func(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
				req := validators_models.NewValidatedAuthorizeRequest()
				req.Subject = newSignedInLocalSubject(t, nil)
				req.Client = storage_models.NewClient()
				req.AuthenticationContextReferenceClasses = []string{
					gois.KnownAcrValuesHomeRealm + "some_idp",
				}
				return req
			},
			wantLogin: true,
		},
		"session beyond client sso lifetime": {
			arrange: func(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
				authTime := fixedInteractionTime.Add(-3700 * time.Second)
				req := validators_models.NewValidatedAuthorizeRequest()
				req.Subject = newSignedInLocalSubject(t, &authTime)
				req.Client = storage_models.NewClient()
				req.Client.UserSsoLifetime = 3600
				return req
			},
			wantLogin: true,
		},
		"local session while client disables local sign-in": {
			arrange: func(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
				req := validators_models.NewValidatedAuthorizeRequest()
				req.Subject = newSignedInLocalSubject(t, nil)
				req.Client = storage_models.NewClient()
				req.Client.EnableLocalLogin = false
				return req
			},
			wantLogin: true,
		},
		"prompt login forces re-authentication": {
			arrange: func(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
				req := validators_models.NewValidatedAuthorizeRequest()
				req.Subject = newSignedInLocalSubject(t, nil)
				req.Client = storage_models.NewClient()
				req.PromptModes = []string{gois.PromptModesLogin}
				req.Raw = url.Values{}
				return req
			},
			wantLogin: true,
		},
		"prompt select_account forces re-authentication": {
			arrange: func(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
				req := validators_models.NewValidatedAuthorizeRequest()
				req.Subject = newSignedInLocalSubject(t, nil)
				req.Client = storage_models.NewClient()
				req.PromptModes = []string{gois.PromptModesSelectAccount}
				req.Raw = url.Values{}
				return req
			},
			wantLogin: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := require.New(t)

			req := tc.arrange(t)
			generator := newInteractionResponseGenerator(newFixedStubClock())

			result := generator.HandleLogin(req)

			a.NotNil(result)
			a.Equal(tc.wantLogin, result.IsLogin)
		})
	}
}
