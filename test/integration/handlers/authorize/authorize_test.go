// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package authorize

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

const (
	knownClientId    = "endpoint-client"
	knownRedirectUri = "https://client.example/callback"
)

func endpointClient(t *testing.T) *storage_models.Client {
	t.Helper()
	client := storage_models.NewClient()
	client.ClientId = knownClientId
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RequireConsent = false
	client.AllowAccessTokensViaBrowser = true
	client.RedirectUris = []string{knownRedirectUri}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId, "api1"}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesImplicit); err != nil {
		t.Fatalf("grant types: %v", err)
	}
	return client
}

func newAuthorizePipeline(t *testing.T) *integration_common.WicketPipeline {
	t.Helper()
	p := integration_common.NewWicketPipeline()
	p.Clients = []*storage_models.Client{endpointClient(t)}
	p.IdentityScopes = []*storage_models.IdentityResource{storage_models.IdentityResourcesOpenId()}
	user := test.NewTestUser()
	user.SubjectId = "endpoint-subject"
	user.Username = "endpoint-user"
	p.Users = []*test.TestUser{user}
	p.Initialize()
	return p
}

// TestAuthorizeEndpointMethodGates exercises the content-type and method
// behaviour of the front-channel authorize endpoint through the full pipeline.
func TestAuthorizeEndpointMethodGates(t *testing.T) {
	t.Parallel()
	p := newAuthorizePipeline(t)
	base := p.TestServer.URL + integration_common.AuthorizeEndpoint

	t.Run("GET is routed to the endpoint", func(t *testing.T) {
		p.BrowserClient.AllowAutoRedirect = false
		resp, err := p.BrowserClient.Get(base)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			t.Fatalf("status = 404, want a routed response")
		}
		if resp.StatusCode >= 500 {
			t.Fatalf("status = %d, want < 500", resp.StatusCode)
		}
	})

	t.Run("non-form POST is rejected with 415", func(t *testing.T) {
		p.BrowserClient.AllowAutoRedirect = false
		resp, err := p.BrowserClient.Post(base, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnsupportedMediaType)
		}
	})

	t.Run("empty urlencoded form POST is processed and ends at 200", func(t *testing.T) {
		p.BrowserClient.AllowAutoRedirect = true
		resp, err := p.BrowserClient.Post(base, "application/x-www-form-urlencoded", strings.NewReader(""))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
	})
}

// TestAuthorizeEndpointErrorPageDispatch drives a range of invalid authorize
// requests and asserts that each is surfaced on the server error page with the
// expected standard error code and carried fields.
func TestAuthorizeEndpointErrorPageDispatch(t *testing.T) {
	for name, tt := range map[string]struct {
		request         *integration_common.AuthorizeUrl
		wantError       string
		wantClientId    string
		wantClientEmpty bool
	}{
		"unknown client is unauthorized_client": {
			request: &integration_common.AuthorizeUrl{
				ClientId:     "ghost-client",
				ResponseType: wicket.ResponseTypesIdToken,
				Scope:        wicket.StandardScopesOpenId,
				RedirectUri:  knownRedirectUri,
				State:        "some-state",
				Nonce:        "some-nonce",
			},
			wantError:    wicket.AuthorizeErrorsUnauthorizedClient.Error(),
			wantClientId: "ghost-client",
		},
		"missing client_id is invalid_request with empty client_id": {
			request: &integration_common.AuthorizeUrl{
				ClientId:     "",
				ResponseType: wicket.ResponseTypesIdToken,
				Scope:        wicket.StandardScopesOpenId,
				RedirectUri:  "https://unregistered.example/callback",
				State:        "some-state",
				Nonce:        "some-nonce",
			},
			wantError:       wicket.AuthorizeErrorsInvalidRequest.Error(),
			wantClientEmpty: true,
		},
		"known client with unregistered redirect is invalid_request": {
			request: &integration_common.AuthorizeUrl{
				ClientId:     knownClientId,
				ResponseType: wicket.ResponseTypesIdToken,
				Scope:        wicket.StandardScopesOpenId,
				RedirectUri:  "https://unregistered.example/callback",
				State:        "some-state",
				Nonce:        "some-nonce",
			},
			wantError:    wicket.AuthorizeErrorsInvalidRequest.Error(),
			wantClientId: knownClientId,
		},
		"invalid response_type is unsupported_response_type": {
			request: &integration_common.AuthorizeUrl{
				ClientId:     knownClientId,
				ResponseType: "not-a-response-type",
				Scope:        wicket.StandardScopesOpenId,
				RedirectUri:  knownRedirectUri,
				State:        "some-state",
				Nonce:        "some-nonce",
			},
			wantError:    wicket.AuthorizeErrorsUnsupportedResponseType.Error(),
			wantClientId: knownClientId,
		},
		"missing scope is invalid_request": {
			request: &integration_common.AuthorizeUrl{
				ClientId:     knownClientId,
				ResponseType: wicket.ResponseTypesIdToken,
				Scope:        "",
				RedirectUri:  knownRedirectUri,
				State:        "some-state",
				Nonce:        "some-nonce",
			},
			wantError:    wicket.AuthorizeErrorsInvalidRequest.Error(),
			wantClientId: knownClientId,
		},
		"overlong scope is invalid_request": {
			request: &integration_common.AuthorizeUrl{
				ClientId:     knownClientId,
				ResponseType: wicket.ResponseTypesIdToken,
				Scope:        strings.Repeat("a", 301),
				RedirectUri:  knownRedirectUri,
				State:        "some-state",
				Nonce:        "some-nonce",
			},
			wantError:    wicket.AuthorizeErrorsInvalidRequest.Error(),
			wantClientId: knownClientId,
		},
	} {
		t.Run(name, func(t *testing.T) {
			// Shares one pipeline per sub-test to keep the interaction captured on
			// the pipeline isolated; a fresh pipeline avoids cross-case state.
			p := newAuthorizePipeline(t)
			resp := p.RequestAuthorizationEndpoint(tt.request)
			if resp != nil {
				t.Fatalf("expected error-page dispatch, got client redirect response")
			}
			if !p.ErrorWasCalled {
				t.Fatal("error page was not triggered")
			}
			if p.ErrorMessage == nil {
				t.Fatal("error message was not captured")
			}
			if p.ErrorMessage.Error != tt.wantError {
				t.Fatalf("error = %q, want %q", p.ErrorMessage.Error, tt.wantError)
			}
			if tt.wantClientEmpty {
				if p.ErrorMessage.ClientId != "" {
					t.Fatalf("client_id = %q, want empty", p.ErrorMessage.ClientId)
				}
			} else if p.ErrorMessage.ClientId != tt.wantClientId {
				t.Fatalf("client_id = %q, want %q", p.ErrorMessage.ClientId, tt.wantClientId)
			}
		})
	}
}
