// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// TestTokenRequestValidationAuthorizationCodeInvalid verifies the failure
// paths of the authorization code grant: code presence and lookup, client
// binding, redirect URI matching, expiry, disabled users, and resource
// checks.
func TestTokenRequestValidationAuthorizationCodeInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId   string
		options    []tokenGrantOption
		parameters func(t *testing.T, f *tokenGrantFixture) url.Values
		wantErr    error
	}{
		"missing code parameter is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestRedirectUri: {"https://server/cb"},
				}
			},
			wantErr: wicket.TokenErrorsInvalidGrant,
		},
		"code that does not exist in the store is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {"invalid"},
					wicket.TokenRequestRedirectUri: {"https://server/cb"},
				}
			},
			wantErr: wicket.TokenErrorsInvalidGrant,
		},
		"code exceeding the maximum length is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {strings.Repeat("x", f.options.InputLengthRestrictions.AuthorizationCode+1)},
					wicket.TokenRequestRedirectUri: {"https://server/cb"},
				}
			},
			wantErr: wicket.TokenErrorsInvalidGrant,
		},
		"code without requested scopes is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				code.RequestedScopes = nil
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantErr: wicket.TokenErrorsInvalidRequest,
		},
		"client without code flow permission is rejected": {
			clientId: "implicitclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("implicitclient", f.now)
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantErr: wicket.TokenErrorsUnauthorizedClient,
		},
		"code issued to a different client is rejected": {
			clientId: "codeclient_restricted",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantErr: wicket.TokenErrorsInvalidGrant,
		},
		"missing redirect_uri is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType: {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:      {handle},
				}
			},
			wantErr: wicket.TokenErrorsUnauthorizedClient,
		},
		"redirect_uri differing from the authorized one is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				code.RedirectUri = "https://server1/cb"
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {"https://server2/cb"},
				}
			},
			wantErr: wicket.TokenErrorsInvalidGrant,
		},
		"expired code is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				code.CreationTime = f.now.Add(-301 * time.Second)
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantErr: wicket.TokenErrorsInvalidGrant,
		},
		"code owned by a disabled user is rejected": {
			clientId: "codeclient",
			options:  []tokenGrantOption{withGrantProfile(validators_mock.NewTestProfileService(false))},
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantErr: wicket.TokenErrorsInvalidGrant,
		},
		"resource parameter exceeding the maximum length is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestResourceCodeParameters(t, f)
				values.Set(wicket.TokenRequestResource, "urn:"+strings.Repeat("a", f.options.InputLengthRestrictions.ResourceGapMaxLength))
				return values
			},
			wantErr: wicket.TokenErrorsInvalidTarget,
		},
		"resource parameter that is not an absolute URI is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestResourceCodeParameters(t, f)
				values.Set(wicket.TokenRequestResource, "api")
				return values
			},
			wantErr: wicket.TokenErrorsInvalidTarget,
		},
		"resource outside the originally authorized set is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestResourceCodeParameters(t, f)
				values.Set(wicket.TokenRequestResource, "urn:api3")
				return values
			},
			wantErr: wicket.TokenErrorsInvalidTarget,
		},
		"repeated resource parameter is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestResourceCodeParameters(t, f)
				values.Add(wicket.TokenRequestResource, "urn:api1")
				values.Add(wicket.TokenRequestResource, "urn:api2")
				return values
			},
			wantErr: wicket.TokenErrorsInvalidTarget,
		},
		"invalid scopes reported by resource validation surface as invalid_scope": {
			clientId: "codeclient",
			options:  []tokenGrantOption{withGrantResourceValidator(grantTestFailingResources([]string{"scope1"}, nil))},
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestResourceCodeParameters(t, f)
				values.Set(wicket.TokenRequestResource, "urn:api1")
				return values
			},
			wantErr: wicket.TokenErrorsInvalidScope,
		},
		"invalid resources reported by resource validation surface as invalid_target": {
			clientId: "codeclient",
			options:  []tokenGrantOption{withGrantResourceValidator(grantTestFailingResources(nil, []string{"urn:api1"}))},
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestResourceCodeParameters(t, f)
				values.Set(wicket.TokenRequestResource, "urn:api1")
				return values
			},
			wantErr: wicket.TokenErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t, tt.options...)
			result, _ := f.validator.ValidateRequest(context.Background(), tt.parameters(t, f), grantTestSecretResult(t, tt.clientId))
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}

// TestTokenRequestValidationAuthorizationCodeReplay verifies that a code is
// consumed on its first exchange and a second exchange of the same handle is
// rejected.
func TestTokenRequestValidationAuthorizationCodeReplay(t *testing.T) {
	t.Parallel()

	f := newTokenGrantFixture(t)
	code := newGrantTestAuthorizationCode("codeclient", f.now)
	handle := storeGrantTestAuthorizationCode(t, f, code)
	parameters := url.Values{
		wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
		wicket.TokenRequestCode:        {handle},
		wicket.TokenRequestRedirectUri: {code.RedirectUri},
	}

	first, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, "codeclient"))
	if first.Error != nil {
		t.Fatalf("first exchange error: %v", first.Error)
	}

	second, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, "codeclient"))
	if !errors.Is(second.Error, wicket.TokenErrorsInvalidGrant) {
		t.Fatalf("second exchange error = %v, want %v", second.Error, wicket.TokenErrorsInvalidGrant)
	}
}

// TestTokenRequestValidationAuthorizationCodeValid verifies the success
// paths of the authorization code grant.
func TestTokenRequestValidationAuthorizationCodeValid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		requestedScopes []string
	}{
		"code with openid scope is exchanged": {
			requestedScopes: []string{"openid"},
		},
		"code including offline_access is exchanged": {
			requestedScopes: []string{"openid", wicket.StandardScopesOfflineAccess},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			code := newGrantTestAuthorizationCode("codeclient", f.now)
			code.RequestedScopes = tt.requestedScopes
			handle := storeGrantTestAuthorizationCode(t, f, code)
			parameters := url.Values{
				wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
				wicket.TokenRequestCode:        {handle},
				wicket.TokenRequestRedirectUri: {code.RedirectUri},
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, "codeclient"))
			if result.Error != nil {
				t.Fatalf("unexpected error: %v (description %q)", result.Error, result.Description)
			}
		})
	}
}

// newGrantTestResourceCodeParameters stores an authorization code that was
// originally granted the urn:api1 and urn:api2 resources and returns the
// matching exchange parameters, ready for a resource parameter to be added.
func newGrantTestResourceCodeParameters(t *testing.T, f *tokenGrantFixture) url.Values {
	t.Helper()

	code := newGrantTestAuthorizationCode("codeclient", f.now)
	code.RequestedScopes = []string{"openid", "scope1"}
	code.RequestedResourceGaps = []string{"urn:api1", "urn:api2"}
	handle := storeGrantTestAuthorizationCode(t, f, code)
	return url.Values{
		wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
		wicket.TokenRequestCode:        {handle},
		wicket.TokenRequestRedirectUri: {code.RedirectUri},
	}
}
