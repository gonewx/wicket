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

// TestTokenRequestValidationPasswordInvalid verifies the failure paths of
// the resource owner password grant: grant type permission, scope checks,
// credential presence and verification, and user status.
func TestTokenRequestValidationPasswordInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId string
		options  []tokenGrantOption
		scope    string
		resource string
		username string
		password string
		wantErr  error
		wantDesc string
	}{
		"client without password grant permission is rejected": {
			clientId: "client",
			scope:    "resource",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsUnauthorizedClient,
		},
		"unknown scope is rejected": {
			clientId: "roclient",
			scope:    "unknown",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"mix of known and unknown scopes is rejected": {
			clientId: "roclient",
			scope:    "resource unknown",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"restricted client requesting unpermitted scope is rejected": {
			clientId: "roclient_restricted",
			scope:    "resource2",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"restricted client mixing permitted and unpermitted scopes is rejected": {
			clientId: "roclient_restricted",
			scope:    "resource resource2",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"missing username and password is rejected": {
			clientId: "roclient",
			scope:    "resource",
			wantErr:  gois.TokenErrorsInvalidGrant,
		},
		"password without username is rejected": {
			clientId: "roclient",
			scope:    "resource",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidGrant,
		},
		"wrong password is rejected with a generic description": {
			clientId: "roclient",
			scope:    "resource",
			username: "bob",
			password: "notbob",
			wantErr:  gois.TokenErrorsInvalidGrant,
			wantDesc: "invalid_username_or_password",
		},
		"user with a password sending no password is rejected": {
			clientId: "roclient",
			scope:    "resource",
			username: "bob_with_password",
			wantErr:  gois.TokenErrorsInvalidGrant,
		},
		"password grant without a configured credential validator is rejected": {
			clientId: "roclient",
			options: []tokenGrantOption{withGrantResourceOwnerValidator(
				NewNotSupportedResourceOwnerPasswordValidator(discardTestLogger()),
			)},
			scope:    "resource",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsUnsupportedGrantType,
		},
		"disabled user is rejected": {
			clientId: "roclient",
			options:  []tokenGrantOption{withGrantProfile(validators_mock.NewTestProfileService(false))},
			scope:    "resource",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidGrant,
		},
		"credential validator error and description are passed through": {
			clientId: "roclient",
			options: []tokenGrantOption{withGrantResourceOwnerValidator(
				validators_mock.NewTestResourceOwnerPasswordValidator(errors.New("failure"), "custom error description"),
			)},
			scope:    "resource",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidGrant,
			wantDesc: "custom error description",
		},
		"invalid scopes reported by resource validation surface as invalid_scope": {
			clientId: "roclient",
			options:  []tokenGrantOption{withGrantResourceValidator(grantTestFailingResources([]string{"scope1"}, nil))},
			scope:    "scope1",
			resource: "urn:api1",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidScope,
		},
		"invalid resources reported by resource validation surface as invalid_target": {
			clientId: "roclient",
			options:  []tokenGrantOption{withGrantResourceValidator(grantTestFailingResources(nil, []string{"urn:api1"}))},
			scope:    "scope1",
			resource: "urn:api1",
			username: "bob",
			password: "bob",
			wantErr:  gois.TokenErrorsInvalidTarget,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t, tt.options...)
			parameters := url.Values{
				gois.TokenRequestGrantType: {gois.GrantTypePassword},
				gois.TokenRequestScope:     {tt.scope},
			}
			if tt.username != "" {
				parameters.Set(gois.TokenRequestUserName, tt.username)
			}
			if tt.password != "" {
				parameters.Set(gois.TokenRequestPassword, tt.password)
			}
			if tt.resource != "" {
				parameters.Set(gois.TokenRequestResource, tt.resource)
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, tt.clientId))
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
			if tt.wantDesc != "" && result.Description != tt.wantDesc {
				t.Fatalf("description = %q, want %q", result.Description, tt.wantDesc)
			}
		})
	}
}

// TestTokenRequestValidationPasswordValid verifies the success paths of the
// resource owner password grant.
func TestTokenRequestValidationPasswordValid(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		clientId     string
		scope        string
		username     string
		password     string
		wantUserName string
	}{
		"user without a password authenticates with the bare username": {
			clientId:     "roclient",
			scope:        "resource",
			username:     "bob_no_password",
			wantUserName: "bob_no_password",
		},
		"matching credentials succeed": {
			clientId: "roclient",
			scope:    "resource",
			username: "bob",
			password: "bob",
		},
		"matching credentials with offline_access succeed": {
			clientId: "roclient",
			scope:    "resource offline_access",
			username: "bob",
			password: "bob",
		},
		"restricted client with permitted scope succeeds": {
			clientId: "roclient_restricted",
			scope:    "resource",
			username: "bob",
			password: "bob",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newTokenGrantFixture(t)
			parameters := url.Values{
				gois.TokenRequestGrantType: {gois.GrantTypePassword},
				gois.TokenRequestScope:     {tt.scope},
				gois.TokenRequestUserName:  {tt.username},
			}
			if tt.password != "" {
				parameters.Set(gois.TokenRequestPassword, tt.password)
			}

			result, _ := f.validator.ValidateRequest(context.Background(), parameters, grantTestSecretResult(t, tt.clientId))
			if result.Error != nil {
				t.Fatalf("unexpected error: %v (description %q)", result.Error, result.Description)
			}
			if tt.wantUserName != "" && result.ValidatedRequest.UserName != tt.wantUserName {
				t.Fatalf("UserName = %q, want %q", result.ValidatedRequest.UserName, tt.wantUserName)
			}
		})
	}
}
