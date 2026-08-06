// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
)

// TestTokenRequestValidationClientCredentialsInvalid verifies grant type
// permission, scope, and resource checks for the client credentials grant.
func TestTokenRequestValidationClientCredentialsInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId  string
		scope     string
		resources func(f *tokenGrantFixture) []string
		wantErr   error
	}{
		"client without client credentials permission is rejected": {
			clientId: "roclient",
			scope:    "resource",
			wantErr:  gois.TokenErrorsUnauthorizedClient,
		},
		"unknown scope is rejected": {
			clientId: "client",
			scope:    "unknown",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"mix of known and unknown scopes is rejected": {
			clientId: "client",
			scope:    "resource unknown",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"restricted client requesting unpermitted scope is rejected": {
			clientId: "client_restricted",
			scope:    "resource2",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"restricted client mixing permitted and unpermitted scopes is rejected": {
			clientId: "client_restricted",
			scope:    "resource resource2",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"explicit identity scope is rejected": {
			clientId: "client",
			scope:    "openid",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"offline_access scope is rejected": {
			clientId: "client",
			scope:    "resource offline_access",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"resource parameter exceeding the maximum length is rejected": {
			clientId: "client",
			scope:    "scope1",
			resources: func(f *tokenGrantFixture) []string {
				return []string{"urn:" + strings.Repeat("a", f.options.InputLengthRestrictions.ResourceGapMaxLength)}
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"resource parameter that is not an absolute URI is rejected": {
			clientId:  "client",
			scope:     "scope1",
			resources: func(f *tokenGrantFixture) []string { return []string{"api"} },
			wantErr:   gois.TokenErrorsInvalidTarget,
		},
		"repeated resource parameter is rejected": {
			clientId:  "client",
			scope:     "scope1",
			resources: func(f *tokenGrantFixture) []string { return []string{"urn:api1", "urn:api2"} },
			wantErr:   gois.TokenErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			parameters := url.Values{
				gois.TokenRequestGrantType: {gois.GrantTypeClientCredentials},
				gois.TokenRequestScope:     {tt.scope},
			}
			if tt.resources != nil {
				for _, resource := range tt.resources(f) {
					parameters.Add(gois.TokenRequestResource, resource)
				}
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, tt.clientId))
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}

// TestTokenRequestValidationClientCredentialsWithoutScopeFiltersIdentityScopes
// verifies that when no scope parameter is sent the request expands to every
// scope the client is allowed, with identity scopes filtered out of the
// client credentials grant.
func TestTokenRequestValidationClientCredentialsWithoutScopeFiltersIdentityScopes(t *testing.T) {
	t.Parallel()

	f := newTokenGrantFixture(t)
	parameters := url.Values{
		gois.TokenRequestGrantType: {gois.GrantTypeClientCredentials},
	}

	result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, "client"))
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}

	resources := result.ValidatedRequest.ValidatedResources.Resources
	wantApiResources := []string{"api", "urn:api1", "urn:api2", "urn:api3"}
	if got := sortedStrings(apiResourceNames(resources.ApiResources())); !reflect.DeepEqual(got, wantApiResources) {
		t.Fatalf("ApiResources = %v, want %v", got, wantApiResources)
	}
	wantApiScopes := []string{"resource", "resource2", "scope1"}
	if got := sortedStrings(apiScopeNames(resources.ApiScopes())); !reflect.DeepEqual(got, wantApiScopes) {
		t.Fatalf("ApiScopes = %v, want %v", got, wantApiScopes)
	}
}

// TestTokenRequestValidationClientCredentialsValid verifies the success
// paths of the client credentials grant.
func TestTokenRequestValidationClientCredentialsValid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId string
		scope    string
	}{
		"client with explicit scope succeeds": {
			clientId: "client",
			scope:    "resource",
		},
		"restricted client without scope falls back to its allowed scopes": {
			clientId: "client_restricted",
		},
		"client permitted for both implicit and client credentials succeeds": {
			clientId: "implicit_and_client_creds_client",
			scope:    "resource",
		},
		"restricted client requesting a permitted scope succeeds": {
			clientId: "client_restricted",
			scope:    "resource",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			parameters := url.Values{
				gois.TokenRequestGrantType: {gois.GrantTypeClientCredentials},
			}
			if tt.scope != "" {
				parameters.Set(gois.TokenRequestScope, tt.scope)
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, tt.clientId))
			if result.Error != nil {
				t.Fatalf("unexpected error: %v (description %q)", result.Error, result.Description)
			}
		})
	}
}
