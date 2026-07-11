// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test/common"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// buildGenerator constructs the subject under test with test doubles. The URL and
// message-store dependencies are nil on purpose: no scenario in this suite reads
// them, and the entry points must not dereference either.
func buildGenerator(clock services.SystemClock, consent services.ConsentService, profile services.ProfileService) *AuthorizeInteractionResponseGenerator {
	return NewAuthorizeInteractionResponseGenerator(
		common.NewTestLogger(),
		clock,
		config_options.NewWicketOptions(),
		consent,
		profile,
		nil,
		nil,
	)
}

// fixedClock returns a clock pinned to the given instant so session-age and
// max_age comparisons are deterministic (no real wall clock in tests).
func fixedClock(at time.Time) *common.StubClock {
	return &common.StubClock{NowFunc: func() time.Time { return at }}
}

// localSubject builds a subject authenticated by the local identity provider,
// optionally carrying an authentication time. The identity-provider field is set
// explicitly so the principal advertises idp="local"; a bare subject would carry
// no idp claim and never reach the idp-sensitive branches.
func localSubject(t *testing.T, authTime *time.Time) *claims.ClaimsPrincipal {
	t.Helper()
	user := models.NewLocalUser(models.WithLocalUserSubjectId("123"))
	user.IdentityProvider = gois.LocalIdentityProvider
	user.AuthenticationTime = authTime
	principal, err := user.CreatePrincipal()
	if err != nil {
		t.Fatalf("create local subject: %v", err)
	}
	return principal
}

// requestedConsentResources builds the consent-flow validated-resource fixture:
// identity resources openid(required)/profile/email, an "api" resource exposing
// read/write/forbidden scopes, and those three api scopes — then narrows the set
// to the requested openid/read/write scopes. openid is the only required scope,
// which is what drives the missing-required-scope rejection.
func requestedConsentResources() *validators_models.ResourceValidationResult {
	api := storage_models.NewApiResource()
	api.Name = "api"
	api.Scopes = []string{"read", "write", "forbidden"}

	read := storage_models.NewApiScope()
	read.Name = "read"
	write := storage_models.NewApiScope()
	write.Name = "write"
	forbidden := storage_models.NewApiScope()
	forbidden.Name = "forbidden"

	full := storage_models.NewResources(
		storage_models.WithResourcesIdentityResources([]*storage_models.IdentityResource{
			storage_models.IdentityResourcesOpenId(),
			storage_models.IdentityResourcesProfile(),
			storage_models.IdentityResourcesEmail(),
		}),
		storage_models.WithResourcesApiResources([]*storage_models.ApiResource{api}),
		storage_models.WithResourcesApiScopes([]*storage_models.ApiScope{read, write, forbidden}),
	)

	return validators_models.NewResourceValidationResultWithResources(full).
		Filter([]string{"openid", "read", "write"})
}

// consentRequest builds the shared consent-flow request preconditions (common to
// every C scenario except the nil-request guard).
func consentRequest(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
	t.Helper()
	req := validators_models.NewValidatedAuthorizeRequest()
	req.ResponseMode = gois.ResponseModesFragment
	req.State = "12345"
	req.RedirectUri = "https://client.com/callback"
	req.RequestedScopes = []string{"openid", "read", "write"}
	req.ValidatedResources = requestedConsentResources()
	req.Client = storage_models.NewClient()
	req.Subject = claims.NewClaimsPrincipal()
	return req
}
