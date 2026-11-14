// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"testing"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

type featureDeclarations struct {
	privateKeyJwt bool
	reads         int
}

func (d *featureDeclarations) PrivateKeyJwtEnabled() bool {
	d.reads++
	return d.privateKeyJwt
}

func TestClientConfigurationValidatorFeatureRule(t *testing.T) {
	const notEnabled = "client requires private_key_jwt client authentication but the feature is not enabled"
	const unsupported = "client declares an unsupported token endpoint authentication method"

	cases := []struct {
		name     string
		method   string
		features validators.ClientFeatureDeclarations
		message  string
	}{
		{"registered and not enabled", "private_key_jwt", &featureDeclarations{}, notEnabled},
		{"registered and enabled", "private_key_jwt", &featureDeclarations{privateKeyJwt: true}, ""},
		{"registered without a declaration source", "private_key_jwt", nil, notEnabled},
		{"not registered and not enabled", "", &featureDeclarations{}, ""},
		{"not registered and enabled", "", &featureDeclarations{privateKeyJwt: true}, ""},
		{"not registered without a declaration source", "", nil, ""},
		{"unknown method", "client_secret_jwt", &featureDeclarations{privateKeyJwt: true}, unsupported},
		{"method in another case", "Private_Key_Jwt", &featureDeclarations{privateKeyJwt: true}, unsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := storage_models.NewClient()
			client.ClientId = "client"
			client.TokenEndpointAuthMethod = tc.method
			context := validators_contexts.NewClientConfigurationValidationContext(client)
			var validator validators.ClientConfigurationValidator = NewClientConfigurationValidator(tc.features)
			validator.Validate(context)
			if tc.message == "" {
				if !context.IsValid || context.ErrorMessage != "" {
					t.Fatalf("context invalid: %q", context.ErrorMessage)
				}
				return
			}
			if context.IsValid || context.ErrorMessage != tc.message {
				t.Fatalf("got valid=%v message=%q, want %q", context.IsValid, context.ErrorMessage, tc.message)
			}
		})
	}
}

func TestClientConfigurationValidatorReadsTheDeclarationOnEveryCall(t *testing.T) {
	declarations := &featureDeclarations{}
	validator := NewClientConfigurationValidator(declarations)
	client := storage_models.NewClient()
	client.TokenEndpointAuthMethod = "private_key_jwt"

	first := validators_contexts.NewClientConfigurationValidationContext(client)
	validator.Validate(first)
	declarations.privateKeyJwt = true
	second := validators_contexts.NewClientConfigurationValidationContext(client)
	validator.Validate(second)
	if first.IsValid || !second.IsValid || declarations.reads != 2 {
		t.Fatalf("first=%v second=%v reads=%d", first.IsValid, second.IsValid, declarations.reads)
	}
}

func TestClientConfigurationValidatorLeavesAnEmptyContextAlone(t *testing.T) {
	validator := NewClientConfigurationValidator(nil)
	validator.Validate(nil)
	context := validators_contexts.NewClientConfigurationValidationContext(nil)
	validator.Validate(context)
	if !context.IsValid {
		t.Fatalf("context without a client was marked invalid")
	}
}
