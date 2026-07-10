// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// newConsentStageRequest builds a validated authorize request positioned at
// the consent-evaluation stage: fragment response mode, an authenticated
// subject, and validated resources filtered down to the requested scopes.
func newConsentStageRequest(t *testing.T) *validators_models.ValidatedAuthorizeRequest {
	t.Helper()

	openid := storage_models.NewIdentityResource()
	openid.Name = "openid"
	profile := storage_models.NewIdentityResource()
	profile.Name = "profile"
	email := storage_models.NewIdentityResource()
	email.Name = "email"

	api := storage_models.NewApiResource()
	api.Name = "api"
	api.Scopes = []string{"read", "write", "forbidden"}

	read := storage_models.NewApiScope()
	read.Name = "read"
	write := storage_models.NewApiScope()
	write.Name = "write"
	forbidden := storage_models.NewApiScope()
	forbidden.Name = "forbidden"

	resources := storage_models.NewResources(
		storage_models.WithResourcesIdentityResources([]*storage_models.IdentityResource{openid, profile, email}),
		storage_models.WithResourcesApiResources([]*storage_models.ApiResource{api}),
		storage_models.WithResourcesApiScopes([]*storage_models.ApiScope{read, write, forbidden}),
	)

	req := validators_models.NewValidatedAuthorizeRequest()
	req.Subject = newSignedInLocalSubject(t, nil)
	req.Client = storage_models.NewClient()
	req.ResponseMode = "fragment"
	req.State = "12345"
	req.RedirectUri = "https://client.com/callback"
	req.RequestedScopes = []string{"openid", "read", "write"}
	req.ValidatedResources = validators_models.NewResourceValidationResultWithResources(resources).
		Filter(req.RequestedScopes)

	return req
}

func TestHandleConsent_AcceptsMissingUserResponse(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	req := newConsentStageRequest(t)
	req.PromptModes = []string{gois.PromptModesConsent}

	generator := newInteractionResponseGenerator(newFixedStubClock())

	result := generator.HandleConsent(req, nil)

	a.NotNil(result)
	a.NoError(result.Error)
}

func TestHandleConsent_PromptConsentWithoutUserResponseShowsConsentPage(t *testing.T) {
	t.Parallel()
	a := require.New(t)

	req := newConsentStageRequest(t)
	req.PromptModes = []string{gois.PromptModesConsent}

	generator := newInteractionResponseGenerator(newFixedStubClock())

	result := generator.HandleConsent(req, nil)

	a.NotNil(result)
	a.False(req.WasConsentShown)
	a.True(result.IsConsent)
}
