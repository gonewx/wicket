// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
	test_common "github.com/gonewx/wicket/test/common"
	validators_mock "github.com/gonewx/wicket/validators/mock"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	resourceIndicatorAlpha = "https://apis.example.com/alpha"
	resourceIndicatorBeta  = "https://apis.example.com/beta"
	resourceIndicatorGamma = "urn:apis:gamma"
)

func TestAuthorizeResourceParameterRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		arrange       func(t *testing.T) (*AuthorizeRequestValidator, url.Values)
		wantErr       error
		wantResources []string
	}{
		"request without resource keeps collected indicators empty": {
			arrange: func(t *testing.T) (*AuthorizeRequestValidator, url.Values) {
				validator, err := createAuthorizeRequestValidator()
				if err != nil {
					t.Fatalf("build validator: %v", err)
				}
				return validator, url.Values{
					gois.AuthorizeRequestClientId:     {"codeclient"},
					gois.AuthorizeRequestScope:        {"openid scope1"},
					gois.AuthorizeRequestRedirectUri:  {"https://server/cb"},
					gois.AuthorizeRequestResponseType: {gois.ResponseTypesCode},
				}
			},
			wantResources: []string{},
		},
		"resource above maximum length is invalid target": {
			arrange: func(t *testing.T) (*AuthorizeRequestValidator, url.Values) {
				validator, err := createAuthorizeRequestValidator()
				if err != nil {
					t.Fatalf("build validator: %v", err)
				}
				return validator, url.Values{
					gois.AuthorizeRequestClientId:     {"codeclient"},
					gois.AuthorizeRequestScope:        {"openid scope1"},
					gois.AuthorizeRequestRedirectUri:  {"https://server/cb"},
					gois.AuthorizeRequestResponseType: {gois.ResponseTypesCode},
					gois.AuthorizeRequestResource:     {"https://server/resources/" + strings.Repeat("a", 512)},
				}
			},
			wantErr: gois.AuthorizeErrorsInvalidTarget,
		},
		"multiple valid resources are all collected": {
			arrange: func(t *testing.T) (*AuthorizeRequestValidator, url.Values) {
				validator := newMultiResourceAuthorizeValidator(t)
				return validator, url.Values{
					gois.AuthorizeRequestClientId:     {"resource-client"},
					gois.AuthorizeRequestScope:        {"alpha.read beta.read gamma.read"},
					gois.AuthorizeRequestRedirectUri:  {"https://client.example.com/callback"},
					gois.AuthorizeRequestResponseType: {gois.ResponseTypesCode},
					gois.AuthorizeRequestResource: {
						resourceIndicatorAlpha,
						resourceIndicatorBeta,
						resourceIndicatorGamma,
					},
				}
			},
			wantResources: []string{
				resourceIndicatorAlpha,
				resourceIndicatorBeta,
				resourceIndicatorGamma,
			},
		},
		"failed scope validation maps to invalid scope": {
			arrange: func(t *testing.T) (*AuthorizeRequestValidator, url.Values) {
				result := validators_models.NewResourceValidationResult()
				result.InvalidScopes = []string{gois.StandardScopesOpenId}
				validator := newMappedResourceAuthorizeValidator(t, result)
				return validator, url.Values{
					gois.AuthorizeRequestClientId:     {"codeclient"},
					gois.AuthorizeRequestScope:        {gois.StandardScopesOpenId},
					gois.AuthorizeRequestRedirectUri:  {"https://server/cb"},
					gois.AuthorizeRequestResponseType: {gois.ResponseTypesCode},
					gois.AuthorizeRequestResource:     {resourceIndicatorAlpha},
				}
			},
			wantErr: gois.AuthorizeErrorsInvalidScope,
		},
		"failed resource validation maps to invalid target before invalid scope": {
			arrange: func(t *testing.T) (*AuthorizeRequestValidator, url.Values) {
				result := validators_models.NewResourceValidationResult()
				result.InvalidScopes = []string{gois.StandardScopesOpenId}
				result.InvalidResourceGaps = []string{resourceIndicatorAlpha}
				validator := newMappedResourceAuthorizeValidator(t, result)
				return validator, url.Values{
					gois.AuthorizeRequestClientId:     {"codeclient"},
					gois.AuthorizeRequestScope:        {gois.StandardScopesOpenId},
					gois.AuthorizeRequestRedirectUri:  {"https://server/cb"},
					gois.AuthorizeRequestResponseType: {gois.ResponseTypesCode},
					gois.AuthorizeRequestResource:     {resourceIndicatorAlpha},
				}
			},
			wantErr: gois.AuthorizeErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			validator, values := tt.arrange(t)
			result := validator.Validate(context.Background(), values, nil)
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
			if tt.wantErr != nil || tt.wantResources == nil {
				return
			}
			got := sortedStrings(result.ValidatedRequest.RequestedResourceIndiators)
			if !reflect.DeepEqual(got, sortedStrings(tt.wantResources)) {
				t.Fatalf("RequestedResourceIndiators = %v, want %v", got, sortedStrings(tt.wantResources))
			}
		})
	}
}

// newMultiResourceAuthorizeValidator wires an AuthorizeRequestValidator whose
// resource store registers several resources selectable via explicit resource
// parameters.
func newMultiResourceAuthorizeValidator(t *testing.T) *AuthorizeRequestValidator {
	t.Helper()

	options := config_options.NewWicketOptions()

	client := storage_models.NewClient()
	client.ClientId = "resource-client"
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RedirectUris = []string{"https://client.example.com/callback"}
	client.AllowedScopes = []string{"alpha.read", "beta.read", "gamma.read"}
	if err := client.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		t.Fatalf("set grant types: %v", err)
	}
	clientStore, err := memory.NewMemoryClientStore([]*storage_models.Client{client})
	if err != nil {
		t.Fatalf("client store: %v", err)
	}

	alphaScope := storage_models.NewApiScope()
	alphaScope.Name = "alpha.read"
	betaScope := storage_models.NewApiScope()
	betaScope.Name = "beta.read"
	gammaScope := storage_models.NewApiScope()
	gammaScope.Name = "gamma.read"

	alpha := storage_models.NewApiResource()
	alpha.Name = resourceIndicatorAlpha
	alpha.Scopes = []string{alphaScope.Name}
	alpha.RequireResourceGap = true
	beta := storage_models.NewApiResource()
	beta.Name = resourceIndicatorBeta
	beta.Scopes = []string{betaScope.Name}
	beta.RequireResourceGap = true
	gamma := storage_models.NewApiResource()
	gamma.Name = resourceIndicatorGamma
	gamma.Scopes = []string{gammaScope.Name}
	gamma.RequireResourceGap = true

	resourceStore, err := memory.NewMemoryResourcesStore(
		nil,
		[]*storage_models.ApiResource{alpha, beta, gamma},
		[]*storage_models.ApiScope{alphaScope, betaScope, gammaScope},
	)
	if err != nil {
		t.Fatalf("resource store: %v", err)
	}

	return NewAuthorizeRequestValidator(
		slog.Default(),
		options,
		services_impl.NewIssuerNameService(options),
		clientStore,
		nil,
		nil,
		NewStrictRedirectUriValidator(),
		NewResourceValidator(resourceStore, NewScopeParser(), slog.Default()),
		nil,
		NewCustomAuthorizeRequestValidator(),
	)
}

// newMappedResourceAuthorizeValidator wires an AuthorizeRequestValidator with
// a stubbed resource validation outcome so the endpoint-level error mapping
// can be asserted in isolation.
func newMappedResourceAuthorizeValidator(t *testing.T, result *validators_models.ResourceValidationResult) *AuthorizeRequestValidator {
	t.Helper()

	options := config_options.NewWicketOptions()

	clientStore, err := memory.NewMemoryClientStore(validators_mock.TestClients{}.Get())
	if err != nil {
		t.Fatalf("client store: %v", err)
	}

	resourceValidator := test_common.NewMockResourceValidator()
	resourceValidator.Result = result

	return NewAuthorizeRequestValidator(
		slog.Default(),
		options,
		services_impl.NewIssuerNameService(options),
		clientStore,
		nil,
		nil,
		NewStrictRedirectUriValidator(),
		resourceValidator,
		nil,
		NewCustomAuthorizeRequestValidator(),
	)
}
