// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package authorize

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// browserTokenClient builds an implicit or hybrid client whose browser
// access-token switch is set as requested.
func browserTokenClient(t *testing.T, clientId string, grantTypes []string, allowBrowserTokens bool) *storage_models.Client {
	t.Helper()
	client := storage_models.NewClient()
	client.ClientId = clientId
	client.RequireClientSecret = false
	client.RequirePkce = false
	client.RequireConsent = false
	client.AllowAccessTokensViaBrowser = allowBrowserTokens
	client.RedirectUris = []string{"https://client.example/callback"}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId, "api1"}
	if err := client.SetAllowedGrantTypes(grantTypes); err != nil {
		t.Fatalf("grant types: %v", err)
	}
	return client
}

func newBrowserTokenPipeline(t *testing.T) *integration_common.WicketPipeline {
	t.Helper()
	p := integration_common.NewWicketPipeline()
	p.Clients = []*storage_models.Client{
		browserTokenClient(t, "implicit-open", wicket.GrantTypesImplicit, true),
		browserTokenClient(t, "implicit-restricted", wicket.GrantTypesImplicit, false),
		browserTokenClient(t, "hybrid-open", wicket.GrantTypesHybrid, true),
		browserTokenClient(t, "hybrid-restricted", wicket.GrantTypesHybrid, false),
	}
	p.IdentityScopes = []*storage_models.IdentityResource{storage_models.IdentityResourcesOpenId()}
	apiScope := storage_models.NewApiScope()
	apiScope.Name = "api1"
	p.ApiScopes = []*storage_models.ApiScope{apiScope}
	user := test.NewTestUser()
	user.SubjectId = "browser-token-subject"
	user.Username = "browser-token-user"
	p.Users = []*test.TestUser{user}
	p.Initialize()
	return p
}

// TestAuthorizeRestrictsAccessTokensViaBrowser drives the authorize endpoint
// across the client browser-token switch, the implicit and hybrid flows, and
// their response_type combinations, asserting which artifacts reach the
// fragment and that a restricted token request lands on the error page.
func TestAuthorizeRestrictsAccessTokensViaBrowser(t *testing.T) {
	cases := map[string]struct {
		clientId        string
		responseType    string
		wantError       bool
		wantIdToken     bool
		wantAccessToken bool
		wantCode        bool
	}{
		"unrestricted implicit id_token": {
			clientId: "implicit-open", responseType: "id_token",
			wantIdToken: true,
		},
		"unrestricted implicit id_token token": {
			clientId: "implicit-open", responseType: "id_token token",
			wantIdToken: true, wantAccessToken: true,
		},
		"restricted implicit id_token": {
			clientId: "implicit-restricted", responseType: "id_token",
			wantIdToken: true,
		},
		"restricted implicit id_token token is rejected": {
			clientId: "implicit-restricted", responseType: "id_token token",
			wantError: true,
		},
		"unrestricted hybrid code id_token": {
			clientId: "hybrid-open", responseType: "code id_token",
			wantIdToken: true, wantCode: true,
		},
		"unrestricted hybrid code id_token token": {
			clientId: "hybrid-open", responseType: "code id_token token",
			wantIdToken: true, wantAccessToken: true, wantCode: true,
		},
		"restricted hybrid code id_token": {
			clientId: "hybrid-restricted", responseType: "code id_token",
			wantIdToken: true, wantCode: true,
		},
		"restricted hybrid code id_token token is rejected": {
			clientId: "hybrid-restricted", responseType: "code id_token token",
			wantError: true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			p := newBrowserTokenPipeline(t)
			if err := p.Login("browser-token-subject"); err != nil {
				t.Fatalf("login: %v", err)
			}

			scope := wicket.StandardScopesOpenId
			if tt.wantAccessToken || tt.wantError {
				scope = wicket.StandardScopesOpenId + " api1"
			}
			authorizeUrl, err := p.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
				ClientId:     tt.clientId,
				ResponseType: tt.responseType,
				Scope:        scope,
				RedirectUri:  "https://client.example/callback",
				State:        "123_state",
				Nonce:        "123_nonce",
			})
			if err != nil {
				t.Fatalf("authorize url: %v", err)
			}

			p.BrowserClient.AllowAutoRedirect = false
			resp, err := p.BrowserClient.Get(authorizeUrl.String())
			if err != nil {
				t.Fatalf("get: %v", err)
			}

			if tt.wantError {
				location := resp.Header.Get("Location")
				if strings.HasPrefix(location, "https://client.example/callback") {
					t.Fatalf("restricted request reached the client redirect: %q", location)
				}
				p.BrowserClient.AllowAutoRedirect = true
				if _, err := p.BrowserClient.Get(authorizeUrl.String()); err != nil {
					t.Fatalf("follow error redirect: %v", err)
				}
				if !p.ErrorWasCalled {
					t.Fatal("error page was not triggered")
				}
				return
			}

			if resp.StatusCode != http.StatusFound {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
			}
			location := resp.Header.Get("Location")
			if !strings.HasPrefix(location, "https://client.example/callback") {
				t.Fatalf("Location = %q, want the registered redirect", location)
			}
			locationUrl, err := url.Parse(location)
			if err != nil {
				t.Fatalf("parse location: %v", err)
			}
			fragments, err := url.ParseQuery(locationUrl.Fragment)
			if err != nil {
				t.Fatalf("parse fragment: %v", err)
			}

			if got := fragments.Get("error"); got != "" {
				t.Fatalf("error = %q, want none", got)
			}
			if (fragments.Get("id_token") != "") != tt.wantIdToken {
				t.Fatalf("id_token presence = %v, want %v", fragments.Get("id_token") != "", tt.wantIdToken)
			}
			if (fragments.Get("access_token") != "") != tt.wantAccessToken {
				t.Fatalf("access_token presence = %v, want %v", fragments.Get("access_token") != "", tt.wantAccessToken)
			}
			if (fragments.Get("code") != "") != tt.wantCode {
				t.Fatalf("code presence = %v, want %v", fragments.Get("code") != "", tt.wantCode)
			}
		})
	}
}
