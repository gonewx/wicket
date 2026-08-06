// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// TestTokenRequestValidationExtensionGrants verifies non-standard grant type
// handling: unregistered grant types, validator error passthrough, user
// status checks, and the success path of a registered validator.
func TestTokenRequestValidationExtensionGrants(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId   string
		grantType  string
		options    []tokenGrantOption
		wantErr    error
		wantAnyErr bool
		wantDesc   string
	}{
		"client credentials client requesting an unregistered grant type is rejected": {
			clientId:  "client",
			grantType: "customGrant",
			wantErr:   gois.TokenErrorsUnsupportedGrantType,
		},
		"extension client requesting an unregistered grant type is rejected": {
			clientId:  "customgrantclient",
			grantType: "unknown_grant_type",
			wantErr:   gois.TokenErrorsUnsupportedGrantType,
		},
		"validator error and description are passed through": {
			clientId:  "customgrantclient",
			grantType: "custom_grant",
			options: []tokenGrantOption{withGrantExtensionValidators(
				validators_mock.NewTestGrantValidator(true, "custom error description"),
			)},
			wantErr:  gois.TokenErrorsInvalidGrant,
			wantDesc: "custom error description",
		},
		"disabled user is rejected": {
			clientId:  "customgrantclient",
			grantType: "custom_grant",
			options: []tokenGrantOption{
				withGrantExtensionValidators(validators_mock.NewTestGrantValidator(false, "")),
				withGrantProfile(validators_mock.NewTestProfileService(false)),
			},
			wantAnyErr: true,
		},
		"registered validator producing a subject succeeds": {
			clientId:  "customgrantclient",
			grantType: "custom_grant",
			options: []tokenGrantOption{withGrantExtensionValidators(
				validators_mock.NewTestGrantValidator(false, ""),
			)},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t, tt.options...)
			parameters := url.Values{
				gois.TokenRequestGrantType: {tt.grantType},
				gois.TokenRequestScope:     {"resource"},
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, tt.clientId))
			if tt.wantAnyErr {
				if result.Error == nil {
					t.Fatal("expected an error for a disabled user")
				}
				return
			}
			if tt.wantErr == nil {
				if result.Error != nil {
					t.Fatalf("unexpected error: %v (description %q)", result.Error, result.Description)
				}
				return
			}
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
			if tt.wantDesc != "" && result.Description != tt.wantDesc {
				t.Fatalf("description = %q, want %q", result.Description, tt.wantDesc)
			}
		})
	}
}
