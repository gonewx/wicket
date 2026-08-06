// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage/memory"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_mock "github.com/gonewx/wicket/validators/mock"
)

// recordingAuthorizeValidator captures invocations of the pluggable authorize
// validation extension point and returns a configurable error.
type recordingAuthorizeValidator struct {
	called bool
	err    error
}

func (v *recordingAuthorizeValidator) Validate(*validators_contexts.CustomAuthorizeRequestValidationContext) error {
	v.called = true
	return v.err
}

// newAuthorizeRequestValidatorWithCustom wires an AuthorizeRequestValidator
// against the shared in-memory fixtures while allowing the caller to inject
// its own custom authorize request validation extension.
func newAuthorizeRequestValidatorWithCustom(custom validators.CustomAuthorizeRequestValidator) (*AuthorizeRequestValidator, error) {
	options := config_options.NewWicketOptions()

	clientStore, err := memory.NewMemoryClientStore(validators_mock.TestClients{}.Get())
	if err != nil {
		return nil, err
	}

	scopes := &validators_mock.TestScopes{}
	resourceStore, err := memory.NewMemoryResourcesStore(scopes.GetIdentity(), scopes.GetApis(), scopes.GetScopes())
	if err != nil {
		return nil, err
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
		custom,
	), nil
}

func TestAuthorizeCustomRuleValidation(t *testing.T) {
	t.Parallel()

	customFailure := errors.New("custom authorize check failed")

	tests := map[string]struct {
		customErr error
		wantErr   error
	}{
		"custom validator runs after protocol validation succeeds": {},
		"custom validator error propagates without translation": {
			customErr: customFailure,
			wantErr:   customFailure,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			custom := &recordingAuthorizeValidator{err: tt.customErr}
			validator, err := newAuthorizeRequestValidatorWithCustom(custom)
			if err != nil {
				t.Fatalf("build validator: %v", err)
			}

			values := url.Values{}
			values.Set(gois.AuthorizeRequestClientId, "codeclient")
			values.Set(gois.AuthorizeRequestScope, gois.StandardScopesOpenId)
			values.Set(gois.AuthorizeRequestRedirectUri, "https://server/cb")
			values.Set(gois.AuthorizeRequestResponseType, gois.ResponseTypesCode)

			result := validator.Validate(context.Background(), values, nil)
			if !errors.Is(result.Error, tt.wantErr) {
				t.Fatalf("error = %v, want %v", result.Error, tt.wantErr)
			}
			if !custom.called {
				t.Fatal("custom authorize validator was not invoked")
			}
			if tt.wantErr != nil && result.Description != tt.wantErr.Error() {
				t.Fatalf("description = %q, want %q", result.Description, tt.wantErr.Error())
			}
		})
	}
}
