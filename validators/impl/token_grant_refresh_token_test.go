// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
)

// TestTokenRequestValidationRefreshTokenInvalid verifies the failure paths
// of the refresh token grant: handle lookup, input length, and resource
// checks.
func TestTokenRequestValidationRefreshTokenInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId   string
		options    []tokenGrantOption
		parameters func(t *testing.T, f *tokenGrantFixture) url.Values
		wantErr    error
	}{
		"handle that does not exist in the store is rejected": {
			clientId: "roclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				return url.Values{
					gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
					gois.TokenRequestRefreshToken: {"nonexistent"},
				}
			},
			wantErr: gois.TokenErrorsInvalidGrant,
		},
		"handle exceeding the maximum length is rejected": {
			clientId: "roclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				return url.Values{
					gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
					gois.TokenRequestRefreshToken: {strings.Repeat("x", f.options.InputLengthRestrictions.RefreshToken+1)},
				}
			},
			wantErr: gois.TokenErrorsInvalidGrant,
		},
		"resource parameter exceeding the maximum length is rejected": {
			clientId: "roclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestScopedRefreshParameters(t, f)
				values.Set(gois.TokenRequestResource, "urn:"+strings.Repeat("a", f.options.InputLengthRestrictions.ResourceGapMaxLength))
				return values
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"resource parameter that is not an absolute URI is rejected": {
			clientId: "roclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestScopedRefreshParameters(t, f)
				values.Set(gois.TokenRequestResource, "api")
				return values
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"repeated resource parameter is rejected": {
			clientId: "roclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestScopedRefreshParameters(t, f)
				values.Add(gois.TokenRequestResource, "urn:api1")
				values.Add(gois.TokenRequestResource, "urn:api2")
				return values
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"invalid scopes reported by resource validation surface as invalid_scope": {
			clientId: "roclient",
			options:  []tokenGrantOption{withGrantResourceValidator(grantTestFailingResources([]string{"scope1"}, nil))},
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestAuthorizedResourceRefreshParameters(t, f)
				values.Set(gois.TokenRequestResource, "urn:api1")
				return values
			},
			wantErr: gois.TokenErrorsInvalidScope,
		},
		"invalid resources reported by resource validation surface as invalid_target": {
			clientId: "roclient",
			options:  []tokenGrantOption{withGrantResourceValidator(grantTestFailingResources(nil, []string{"urn:api1"}))},
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestAuthorizedResourceRefreshParameters(t, f)
				values.Set(gois.TokenRequestResource, "urn:api1")
				return values
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
		"resource outside the originally authorized set is rejected": {
			clientId: "roclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				values := newGrantTestAuthorizedResourceRefreshParameters(t, f)
				values.Set(gois.TokenRequestResource, "urn:api3")
				return values
			},
			wantErr: gois.TokenErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t, tt.options...)
			result := f.validator.ValidateRequest(tt.parameters(t, f), grantTestSecretResult(t, tt.clientId))
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}

// TestTokenRequestValidationRefreshTokenValid verifies the success paths of
// the refresh token grant.
func TestTokenRequestValidationRefreshTokenValid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId string
	}{
		"stored token is exchanged": {
			clientId: "roclient",
		},
		"restricted client with refresh permission exchanges its token": {
			clientId: "roclient_restricted_refresh",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			token := newGrantTestRefreshToken(tt.clientId, f.now)
			handle := storeGrantTestRefreshToken(t, f, token)
			parameters := url.Values{
				gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
				gois.TokenRequestRefreshToken: {handle},
			}

			result := f.validator.ValidateRequest(parameters, grantTestSecretResult(t, tt.clientId))
			if result.Error != nil {
				t.Fatalf("unexpected error: %v (description %q)", result.Error, result.Description)
			}
		})
	}
}

// newGrantTestScopedRefreshParameters stores a refresh token whose original
// authorization carried only the scope1 scope and returns the matching
// exchange parameters, ready for a resource parameter to be added.
func newGrantTestScopedRefreshParameters(t *testing.T, f *tokenGrantFixture) url.Values {
	t.Helper()

	token := newGrantTestRefreshToken("roclient", f.now)
	token.AuthorizedScopes = []string{"scope1"}
	handle := storeGrantTestRefreshToken(t, f, token)
	return url.Values{
		gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
		gois.TokenRequestRefreshToken: {handle},
	}
}

// newGrantTestAuthorizedResourceRefreshParameters stores a refresh token
// whose original authorization carried the urn:api1 and urn:api2 resources
// and returns the matching exchange parameters, ready for a resource
// parameter to be added.
func newGrantTestAuthorizedResourceRefreshParameters(t *testing.T, f *tokenGrantFixture) url.Values {
	t.Helper()

	token := newGrantTestRefreshToken("roclient", f.now)
	token.AuthorizedScopes = []string{"scope1"}
	token.AuthorizedResourceGaps = []string{"urn:api1", "urn:api2"}
	handle := storeGrantTestRefreshToken(t, f, token)
	return url.Values{
		gois.TokenRequestGrantType:    {gois.GrantTypeRefreshToken},
		gois.TokenRequestRefreshToken: {handle},
	}
}
