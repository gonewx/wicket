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

type highSecurityDeclarations struct {
	profile bool
}

func (highSecurityDeclarations) PrivateKeyJwtEnabled() bool { return true }

func (highSecurityDeclarations) PrivateKeyJwtSigningAlgorithms() []string {
	return []string{"PS256", "ES256"}
}

func (highSecurityDeclarations) DPoPEnabled() bool { return true }

func (highSecurityDeclarations) PushedAuthorizationRequestsEnabled() bool { return true }

func (highSecurityDeclarations) ClientCertificateMethodEnabled(string) bool { return true }

func (d highSecurityDeclarations) HighSecurityProfileEnabled() bool { return d.profile }

// compliantHighSecurityClient returns a client that complies with the high
// security profile.
func compliantHighSecurityClient() *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = "client"
	client.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
	client.RequireDPoP = true
	client.AuthorizationCodeLifetime = 60
	client.RedirectUris = []string{"https://client.example/cb"}
	_ = client.SetAllowedGrantTypes(wicket.GrantTypesCodeAndClientCredentials)
	return client
}

func TestHighSecurityProfileRules(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		configure func(*storage_models.Client)
		conflict  string
		// ruleOnly skips the validator chain, whose earlier rules need
		// metadata the case does not register.
		ruleOnly bool
	}{
		"private_key_jwt complies": {configure: func(*storage_models.Client) {}},
		"tls_client_auth complies": {configure: func(c *storage_models.Client) {
			c.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsTlsClientAuth
		}, ruleOnly: true},
		"self_signed_tls_client_auth complies": {configure: func(c *storage_models.Client) {
			c.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
		}, ruleOnly: true},
		"shared secret conflicts":         {configure: func(c *storage_models.Client) { c.TokenEndpointAuthMethod = "" }, conflict: "token endpoint authentication method"},
		"public client conflicts":         {configure: func(c *storage_models.Client) { c.TokenEndpointAuthMethod = ""; c.RequireClientSecret = false }, conflict: "token endpoint authentication method"},
		"certificate bound tokens comply": {configure: func(c *storage_models.Client) { c.RequireDPoP = false; c.TlsClientCertificateBoundAccessTokens = true }, ruleOnly: true},
		"no sender constraint conflicts":  {configure: func(c *storage_models.Client) { c.RequireDPoP = false }, conflict: "neither DPoP nor certificate bound"},
		"PKCE not required conflicts":     {configure: func(c *storage_models.Client) { c.RequirePkce = false }, conflict: "PKCE is not required"},
		"plain PKCE conflicts":            {configure: func(c *storage_models.Client) { c.AllowPlainTextPkce = true }, conflict: "plain PKCE is allowed"},
		"password grant conflicts": {configure: func(c *storage_models.Client) {
			_ = c.SetAllowedGrantTypes(wicket.GrantTypesResourceOwnerPasswordAndClientCredentials)
		}, conflict: "grant type password"},
		"implicit grant conflicts":              {configure: func(c *storage_models.Client) { _ = c.SetAllowedGrantTypes(wicket.GrantTypesImplicit) }, conflict: "grant type implicit"},
		"hybrid grant conflicts":                {configure: func(c *storage_models.Client) { _ = c.SetAllowedGrantTypes(wicket.GrantTypesHybrid) }, conflict: "grant type hybrid"},
		"code lifetime of 61 seconds conflicts": {configure: func(c *storage_models.Client) { c.AuthorizationCodeLifetime = 61 }, conflict: "authorization code lifetime"},
		"request_uri lifetime of 599 complies":  {configure: func(c *storage_models.Client) { c.RequestUriLifetime = 599 }},
		"request_uri lifetime of 600 conflicts": {configure: func(c *storage_models.Client) { c.RequestUriLifetime = 600 }, conflict: "request_uri lifetime"},
		"http on 127.0.0.1 complies":            {configure: func(c *storage_models.Client) { c.RedirectUris = []string{"http://127.0.0.1:8080/cb"} }},
		"http on [::1] complies":                {configure: func(c *storage_models.Client) { c.RedirectUris = []string{"http://[::1]:8080/cb"} }},
		"http on localhost conflicts":           {configure: func(c *storage_models.Client) { c.RedirectUris = []string{"http://localhost/cb"} }, conflict: "redirect URI uses http"},
		"http on a domain conflicts": {configure: func(c *storage_models.Client) {
			c.RedirectUris = []string{"https://ok.example/cb", "http://client.example/cb"}
		}, conflict: "redirect URI uses http"},
		"custom scheme complies": {configure: func(c *storage_models.Client) { c.RedirectUris = []string{"com.example.app:/cb"} }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := compliantHighSecurityClient()
			tc.configure(client)

			conflicts := HighSecurityProfileConflicts(client)
			if tc.conflict == "" {
				if len(conflicts) != 0 {
					t.Fatalf("unexpected conflicts %q", conflicts)
				}
			} else if len(conflicts) != 1 || !strings.Contains(conflicts[0], tc.conflict) {
				t.Fatalf("conflicts %q, want one containing %q", conflicts, tc.conflict)
			}

			if tc.ruleOnly {
				return
			}
			for _, profile := range []bool{false, true} {
				context := validators_contexts.NewClientConfigurationValidationContext(client)
				var validator validators.ClientConfigurationValidator = NewClientConfigurationValidator(highSecurityDeclarations{profile: profile})
				validator.Validate(context)
				wantInvalid := profile && tc.conflict != ""
				if context.IsValid == wantInvalid {
					t.Fatalf("profile=%v: valid=%v message=%q", profile, context.IsValid, context.ErrorMessage)
				}
				if wantInvalid && !strings.HasPrefix(context.ErrorMessage, "client conflicts with the high security profile: ") {
					t.Fatalf("message %q does not name the profile", context.ErrorMessage)
				}
			}
		})
	}
}

func TestHighSecurityProfileRuleRunsAfterFeatureRules(t *testing.T) {
	t.Parallel()
	client := compliantHighSecurityClient()
	client.TokenEndpointAuthMethod = "client_secret_jwt"
	context := validators_contexts.NewClientConfigurationValidationContext(client)
	NewClientConfigurationValidator(highSecurityDeclarations{profile: true}).Validate(context)
	if context.ErrorMessage != "client declares an unsupported token endpoint authentication method" {
		t.Fatalf("message %q", context.ErrorMessage)
	}
}

func TestHighSecurityProfileConflictsListsEveryItem(t *testing.T) {
	t.Parallel()
	client := storage_models.NewClient()
	client.RequirePkce = false
	client.RedirectUris = []string{"http://client.example/cb"}
	_ = client.SetAllowedGrantTypes(wicket.GrantTypesResourceOwnerPasswordAndClientCredentials)
	if got := len(HighSecurityProfileConflicts(client)); got != 6 {
		t.Fatalf("got %d conflicts: %q", got, HighSecurityProfileConflicts(client))
	}
}
