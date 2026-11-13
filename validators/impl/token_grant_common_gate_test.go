// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
)

// TestTokenRequestValidationRejectsNilArguments verifies that a token
// request cannot proceed without request parameters or a client validation
// result.
func TestTokenRequestValidationRejectsNilArguments(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		parameters func(t *testing.T, f *tokenGrantFixture) url.Values
	}{
		"nil parameters and nil client validation result": {
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values { return nil },
		},
		"valid authorization code parameters with nil client validation result": {
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				return url.Values{
					wicket.TokenRequestGrantType:   {wicket.GrantTypeAuthorizationCode},
					wicket.TokenRequestCode:        {"handle"},
					wicket.TokenRequestRedirectUri: {"https://server/cb"},
				}
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			result, _ := f.validator.ValidateRequest(context.Background(), tt.parameters(t, f), nil)
			if result.Error == nil {
				t.Fatal("expected an error for nil client validation result")
			}
		})
	}
}

// TestTokenRequestValidationGrantTypeAndProtocolGate verifies the checks
// that run before any grant specific validation: protocol type and grant
// type presence/support.
func TestTokenRequestValidationGrantTypeAndProtocolGate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId   string
		parameters func(t *testing.T, f *tokenGrantFixture) url.Values
		wantErr    error
	}{
		"unknown grant type is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestGrantType:   {"unknown"},
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantErr: wicket.TokenErrorsUnsupportedGrantType,
		},
		"client with non OpenID Connect protocol type is rejected": {
			clientId: "client.cred.saml2p-gap",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				return url.Values{
					wicket.TokenRequestGrantType: {wicket.GrantTypeClientCredentials},
				}
			},
			wantErr: wicket.TokenErrorsInvalidClient,
		},
		"missing grant type is rejected": {
			clientId: "codeclient",
			parameters: func(t *testing.T, f *tokenGrantFixture) url.Values {
				code := newGrantTestAuthorizationCode("codeclient", f.now)
				handle := storeGrantTestAuthorizationCode(t, f, code)
				return url.Values{
					wicket.TokenRequestCode:        {handle},
					wicket.TokenRequestRedirectUri: {code.RedirectUri},
				}
			},
			wantErr: wicket.TokenErrorsUnsupportedGrantType,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			result, _ := f.validator.ValidateRequest(context.Background(), tt.parameters(t, f), grantTestSecretResult(t, tt.clientId))
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
		})
	}
}
