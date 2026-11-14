// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// stubClientAuthenticator returns a fixed result and counts its calls.
type stubClientAuthenticator struct {
	result *validators_models.ClientSecretValidationResult
	calls  int
}

func (s *stubClientAuthenticator) Validate(*http.Request) *validators_models.ClientSecretValidationResult {
	s.calls++
	return s.result
}

func authenticatedAs(client *storage_models.Client, secretType string) *validators_models.ClientSecretValidationResult {
	result := validators_models.NewClientSecretValidationResult()
	result.Client = client
	result.Secret = &models.ParsedSecret{Id: client.ClientId, Type: secretType}
	return result
}

func tokenRequest(body url.Values, query string) *http.Request {
	target := "/connect/token"
	if query != "" {
		target += "?" + query
	}
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

func TestClientCredentialsAuthenticationValidator(t *testing.T) {
	newClient := func(configure func(*storage_models.Client)) *storage_models.Client {
		client := storage_models.NewClient()
		client.ClientId = "client"
		_ = client.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials})
		configure(client)
		return client
	}
	public := newClient(func(c *storage_models.Client) { c.RequireClientSecret = false })
	confidential := newClient(func(c *storage_models.Client) { c.RequireClientSecret = true })
	assertion := newClient(func(c *storage_models.Client) {
		c.RequireClientSecret = false
		c.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsPrivateKeyJwt
	})
	tls := newClient(func(c *storage_models.Client) {
		c.RequireClientSecret = false
		c.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsTlsClientAuth
	})
	selfSigned := newClient(func(c *storage_models.Client) {
		c.RequireClientSecret = false
		c.TokenEndpointAuthMethod = wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
	})
	implicitOnly := newClient(func(c *storage_models.Client) {
		c.RequireClientSecret = true
		_ = c.SetAllowedGrantTypes([]string{wicket.GrantTypeImplicit})
	})

	clientCredentials := url.Values{wicket.TokenRequestGrantType: {wicket.GrantTypeClientCredentials}, "client_id": {"client"}}
	authorizationCode := url.Values{wicket.TokenRequestGrantType: {wicket.GrantTypeAuthorizationCode}, "client_id": {"client"}}
	refreshToken := url.Values{wicket.TokenRequestGrantType: {wicket.GrantTypeRefreshToken}, "client_id": {"client"}}
	onlyClientId := url.Values{"client_id": {"client"}}

	cases := []struct {
		name    string
		inner   *validators_models.ClientSecretValidationResult
		body    url.Values
		query   string
		refused bool
	}{
		{"public client, client_credentials", authenticatedAs(public, wicket.ParsedSecretTypesNoSecret), clientCredentials, "", true},
		{"public client with a secret, client_credentials", authenticatedAs(public, wicket.ParsedSecretTypesSharedSecret), clientCredentials, "", true},
		{"public client, grant type in the query string", authenticatedAs(public, wicket.ParsedSecretTypesNoSecret), onlyClientId, "grant_type=client_credentials", true},
		{"public client presenting an assertion without the method", authenticatedAs(public, wicket.ParsedSecretTypesJwtBearer), clientCredentials, "", true},
		{"public client presenting a certificate without the method", authenticatedAs(public, wicket.ParsedSecretTypesX509Certificate), clientCredentials, "", true},
		{"private_key_jwt client without an assertion", authenticatedAs(assertion, wicket.ParsedSecretTypesNoSecret), clientCredentials, "", true},
		{"tls client without a certificate", authenticatedAs(tls, wicket.ParsedSecretTypesNoSecret), clientCredentials, "", true},
		{"implicit only client", authenticatedAs(implicitOnly, wicket.ParsedSecretTypesSharedSecret), clientCredentials, "", true},
		{"result without a client", validators_models.NewClientSecretValidationResult(), clientCredentials, "", true},
		{"confidential client", authenticatedAs(confidential, wicket.ParsedSecretTypesSharedSecret), clientCredentials, "", false},
		{"private_key_jwt client", authenticatedAs(assertion, wicket.ParsedSecretTypesJwtBearer), clientCredentials, "", false},
		{"tls_client_auth client", authenticatedAs(tls, wicket.ParsedSecretTypesX509Certificate), clientCredentials, "", false},
		{"self_signed_tls_client_auth client", authenticatedAs(selfSigned, wicket.ParsedSecretTypesX509Certificate), clientCredentials, "", false},
		{"public client, authorization_code", authenticatedAs(public, wicket.ParsedSecretTypesNoSecret), authorizationCode, "", false},
		{"public client, refresh_token", authenticatedAs(public, wicket.ParsedSecretTypesNoSecret), refreshToken, "", false},
		{"public client, no grant type", authenticatedAs(public, wicket.ParsedSecretTypesNoSecret), onlyClientId, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := &bytes.Buffer{}
			inner := &stubClientAuthenticator{result: tc.inner}
			validator := NewClientCredentialsAuthenticationValidator(inner, slog.New(slog.NewTextHandler(logs, nil)))
			result := validator.Validate(tokenRequest(tc.body, tc.query))
			if inner.calls != 1 {
				t.Fatalf("inner called %d times, want 1", inner.calls)
			}
			if !tc.refused {
				if result != tc.inner {
					t.Fatal("an accepted result was not passed through unchanged")
				}
				return
			}
			if result == nil || !errors.Is(result.Error, wicket.TokenErrorsInvalidClient) {
				t.Fatalf("result = %+v, want invalid_client", result)
			}
			if result.Description != "" || result.Client != nil {
				t.Fatal("the refusal carries a description or the client")
			}
			if !strings.Contains(logs.String(), "client_id=") {
				t.Fatalf("refusal not logged: %s", logs.String())
			}
		})
	}
}

func TestClientCredentialsAuthenticationValidatorPassesInnerFailures(t *testing.T) {
	failure := validators_models.NewClientSecretValidationResult()
	failure.Error = errors.New("inner failure")
	failure.Description = "kept"
	for _, inner := range []*validators_models.ClientSecretValidationResult{failure, nil} {
		stub := &stubClientAuthenticator{result: inner}
		result := NewClientCredentialsAuthenticationValidator(stub, nil).Validate(tokenRequest(url.Values{wicket.TokenRequestGrantType: {wicket.GrantTypeClientCredentials}}, ""))
		if result != inner {
			t.Fatalf("result = %+v, want the inner result unchanged", result)
		}
	}
}

func TestClientCredentialsAuthenticationValidatorParsesAnUnparsedForm(t *testing.T) {
	public := storage_models.NewClient()
	public.ClientId = "client"
	public.RequireClientSecret = false
	stub := &stubClientAuthenticator{result: authenticatedAs(public, wicket.ParsedSecretTypesNoSecret)}
	request := tokenRequest(url.Values{wicket.TokenRequestGrantType: {wicket.GrantTypeClientCredentials}}, "")
	if request.Form != nil {
		t.Fatal("test request arrives parsed")
	}
	result := NewClientCredentialsAuthenticationValidator(stub, nil).Validate(request)
	if result == nil || !errors.Is(result.Error, wicket.TokenErrorsInvalidClient) {
		t.Fatalf("result = %+v, want invalid_client", result)
	}
}
