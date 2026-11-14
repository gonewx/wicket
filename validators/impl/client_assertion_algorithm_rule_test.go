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

// assertionAlgorithmDeclarations declares private_key_jwt enabled with the
// given server algorithms.
type assertionAlgorithmDeclarations struct {
	algorithms []string
}

func (d assertionAlgorithmDeclarations) PrivateKeyJwtEnabled() bool { return d.algorithms != nil }

func (d assertionAlgorithmDeclarations) PrivateKeyJwtSigningAlgorithms() []string {
	return d.algorithms
}

func TestClientConfigurationValidatorAssertionAlgorithmRule(t *testing.T) {
	server := assertionAlgorithmDeclarations{algorithms: []string{"RS256", "ES256"}}
	privateKeyJwt := wicket.EndpointAuthenticationMethodsPrivateKeyJwt

	cases := []struct {
		name       string
		features   validators.ClientFeatureDeclarations
		method     string
		algorithms []string
		valid      bool
	}{
		{"empty list without a method", nil, "", nil, true},
		{"empty list with private_key_jwt", server, privateKeyJwt, nil, true},
		{"subset of the server algorithms", server, privateKeyJwt, []string{"ES256"}, true},
		{"all server algorithms", server, privateKeyJwt, []string{"RS256", "ES256"}, true},
		{"list without a method", server, "", []string{"ES256"}, false},
		{"list with a tls method", server, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth, []string{"ES256"}, false},
		{"algorithm outside the server list", server, privateKeyJwt, []string{"ES256", "PS256"}, false},
		{"symmetric algorithm", server, privateKeyJwt, []string{"HS256"}, false},
		{"empty value", server, privateKeyJwt, []string{""}, false},
		{"declarations without the report", &featureDeclarations{privateKeyJwt: true}, privateKeyJwt, []string{"ES256"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := storage_models.NewClient()
			client.ClientId = "client"
			client.TokenEndpointAuthMethod = tc.method
			client.TokenEndpointAuthSigningAlgorithms = tc.algorithms
			if tc.method == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth {
				client.Jwks = `{"keys":[]}`
			}
			context := validators_contexts.NewClientConfigurationValidationContext(client)
			features := tc.features
			if tc.method == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth {
				features = tlsAndAssertionDeclarations{assertionAlgorithmDeclarations: server}
			}
			NewClientConfigurationValidator(features).Validate(context)
			if context.IsValid != tc.valid {
				t.Fatalf("IsValid = %v (%q), want %v", context.IsValid, context.ErrorMessage, tc.valid)
			}
			if !tc.valid && !strings.Contains(context.ErrorMessage, "signing algorithm") {
				t.Fatalf("ErrorMessage = %q, want the signing algorithm rule", context.ErrorMessage)
			}
		})
	}
}

// tlsAndAssertionDeclarations declares both private_key_jwt and mutual TLS
// enabled, so only the algorithm rule can fail.
type tlsAndAssertionDeclarations struct {
	assertionAlgorithmDeclarations
}

func (tlsAndAssertionDeclarations) ClientCertificateAuthenticationEnabled() bool { return true }

func (tlsAndAssertionDeclarations) ClientCertificateMethodEnabled(string) bool { return true }
