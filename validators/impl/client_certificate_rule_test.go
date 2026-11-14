// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"testing"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
)

// certificateDeclarations declares a set of available mutual TLS methods.
type certificateDeclarations struct {
	methods map[string]bool
}

func (certificateDeclarations) PrivateKeyJwtEnabled() bool { return false }

func (d certificateDeclarations) ClientCertificateMethodEnabled(method string) bool {
	return d.methods[method]
}

func TestClientConfigurationValidatorClientCertificateRule(t *testing.T) {
	const tls = wicket.EndpointAuthenticationMethodsTlsClientAuth
	const selfSigned = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
	both := certificateDeclarations{methods: map[string]bool{tls: true, selfSigned: true}}
	onlySelfSigned := certificateDeclarations{methods: map[string]bool{selfSigned: true}}

	cases := []struct {
		name      string
		method    string
		features  validators.ClientFeatureDeclarations
		configure func(*storage_models.Client)
		valid     bool
	}{
		{"pki with subject dn", tls, both, func(c *storage_models.Client) { c.TlsClientAuthSubjectDn = "CN=client" }, true},
		{"pki with san dns", tls, both, func(c *storage_models.Client) { c.TlsClientAuthSanDns = "client.example" }, true},
		{"pki with san uri", tls, both, func(c *storage_models.Client) { c.TlsClientAuthSanUri = "https://client.example" }, true},
		{"pki with san ip", tls, both, func(c *storage_models.Client) { c.TlsClientAuthSanIp = "192.0.2.1" }, true},
		{"pki with san email", tls, both, func(c *storage_models.Client) { c.TlsClientAuthSanEmail = "client@example.test" }, true},
		{"pki without subject attribute", tls, both, func(*storage_models.Client) {}, false},
		{"pki with two subject attributes", tls, both, func(c *storage_models.Client) {
			c.TlsClientAuthSubjectDn = "CN=client"
			c.TlsClientAuthSanDns = "client.example"
		}, false},
		{"pki not enabled", tls, onlySelfSigned, func(c *storage_models.Client) { c.TlsClientAuthSubjectDn = "CN=client" }, false},
		{"pki without declarations", tls, nil, func(c *storage_models.Client) { c.TlsClientAuthSubjectDn = "CN=client" }, false},
		{"pki with declarations lacking the method report", tls, &featureDeclarations{privateKeyJwt: true}, func(c *storage_models.Client) { c.TlsClientAuthSubjectDn = "CN=client" }, false},
		{"self-signed with jwks", selfSigned, onlySelfSigned, func(c *storage_models.Client) { c.Jwks = `{"keys":[]}` }, true},
		{"self-signed without jwks", selfSigned, both, func(*storage_models.Client) {}, false},
		{"self-signed not enabled", selfSigned, certificateDeclarations{}, func(c *storage_models.Client) { c.Jwks = `{"keys":[]}` }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := storage_models.NewClient()
			client.ClientId = "client"
			client.TokenEndpointAuthMethod = tc.method
			tc.configure(client)
			context := validators_contexts.NewClientConfigurationValidationContext(client)
			NewClientConfigurationValidator(tc.features).Validate(context)
			if context.IsValid != tc.valid {
				t.Fatalf("IsValid = %v (%q), want %v", context.IsValid, context.ErrorMessage, tc.valid)
			}
			if !tc.valid && context.ErrorMessage == "" {
				t.Fatalf("invalid configuration without an error message")
			}
		})
	}
}
