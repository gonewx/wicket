// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

// boundTokenDeclarations declares whether mutual TLS client authentication,
// and with it certificate bound access tokens, is enabled.
type boundTokenDeclarations struct {
	enabled bool
}

func (boundTokenDeclarations) PrivateKeyJwtEnabled() bool { return false }

func (d boundTokenDeclarations) ClientCertificateAuthenticationEnabled() bool { return d.enabled }

func (d boundTokenDeclarations) ClientCertificateMethodEnabled(string) bool { return d.enabled }

func TestClientConfigurationValidatorCertificateBoundRule(t *testing.T) {
	enabled := boundTokenDeclarations{enabled: true}

	cases := []struct {
		name       string
		registered bool
		features   validators.ClientFeatureDeclarations
		configure  func(*storage_models.Client)
		valid      bool
		message    string
	}{
		{"not registered without the feature", false, nil, func(*storage_models.Client) {}, true, ""},
		{"not registered with front channel tokens", false, nil, func(c *storage_models.Client) { c.AllowAccessTokensViaBrowser = true }, true, ""},
		{"not registered public client", false, nil, func(c *storage_models.Client) { c.RequireClientSecret = false }, true, ""},
		{"registered confidential client", true, enabled, func(*storage_models.Client) {}, true, ""},
		{"registered mutual TLS client", true, enabled, func(c *storage_models.Client) {
			c.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
			c.Jwks = `{"keys":[]}`
		}, true, ""},
		{"feature not enabled", true, boundTokenDeclarations{}, func(*storage_models.Client) {}, false, "not enabled"},
		{"no declarations", true, nil, func(*storage_models.Client) {}, false, "not enabled"},
		{"declarations without the report", true, &featureDeclarations{privateKeyJwt: true}, func(*storage_models.Client) {}, false, "not enabled"},
		{"front channel tokens", true, enabled, func(c *storage_models.Client) { c.AllowAccessTokensViaBrowser = true }, false, "browser"},
		{"public client", true, enabled, func(c *storage_models.Client) { c.RequireClientSecret = false }, false, "public client"},
		{"an earlier error is kept", true, enabled, func(c *storage_models.Client) {
			c.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
			c.AllowAccessTokensViaBrowser = true
		}, false, "inline JWK Set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := storage_models.NewClient()
			client.ClientId = "client"
			client.TlsClientCertificateBoundAccessTokens = tc.registered
			tc.configure(client)
			context := validators_contexts.NewClientConfigurationValidationContext(client)
			NewClientConfigurationValidator(tc.features).Validate(context)
			if context.IsValid != tc.valid {
				t.Fatalf("IsValid = %v (%q), want %v", context.IsValid, context.ErrorMessage, tc.valid)
			}
			if !tc.valid && !strings.Contains(context.ErrorMessage, tc.message) {
				t.Fatalf("ErrorMessage = %q, want it to mention %q", context.ErrorMessage, tc.message)
			}
		})
	}
}
