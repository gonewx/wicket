// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"strings"
	"testing"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

// pushedDeclarations declares whether pushed authorization requests are
// enabled.
type pushedDeclarations struct{ enabled bool }

func (pushedDeclarations) PrivateKeyJwtEnabled() bool { return false }

func (d pushedDeclarations) PushedAuthorizationRequestsEnabled() bool { return d.enabled }

func TestClientConfigurationValidatorPushedAuthorizationRule(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		features  validators.ClientFeatureDeclarations
		configure func(*storage_models.Client)
		message   string
	}{
		"nothing registered":             {features: nil, configure: func(*storage_models.Client) {}},
		"lifetime without the feature":   {features: nil, configure: func(c *storage_models.Client) { c.RequestUriLifetime = 30 }},
		"required with the feature":      {features: pushedDeclarations{enabled: true}, configure: func(c *storage_models.Client) { c.RequirePushedAuthorizationRequests = true }},
		"required without the feature":   {features: pushedDeclarations{}, configure: func(c *storage_models.Client) { c.RequirePushedAuthorizationRequests = true }, message: "not enabled"},
		"required without declarations":  {features: nil, configure: func(c *storage_models.Client) { c.RequirePushedAuthorizationRequests = true }, message: "not enabled"},
		"required without the report":    {features: &featureDeclarations{}, configure: func(c *storage_models.Client) { c.RequirePushedAuthorizationRequests = true }, message: "not enabled"},
		"negative lifetime":              {features: pushedDeclarations{enabled: true}, configure: func(c *storage_models.Client) { c.RequestUriLifetime = -1 }, message: "negative"},
		"negative lifetime, feature off": {features: nil, configure: func(c *storage_models.Client) { c.RequestUriLifetime = -1 }, message: "negative"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := storage_models.NewClient()
			client.ClientId = "client"
			tc.configure(client)
			context := validators_contexts.NewClientConfigurationValidationContext(client)
			NewClientConfigurationValidator(tc.features).Validate(context)
			if tc.message == "" {
				if !context.IsValid {
					t.Fatalf("IsValid = false (%q), want true", context.ErrorMessage)
				}
				return
			}
			if context.IsValid || !strings.Contains(context.ErrorMessage, tc.message) {
				t.Fatalf("IsValid = %v, ErrorMessage = %q, want an error mentioning %q", context.IsValid, context.ErrorMessage, tc.message)
			}
		})
	}
}
