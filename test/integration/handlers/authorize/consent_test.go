// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package authorize

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	models_messages "github.com/gonewx/wicket/models/messages"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	test_common "github.com/gonewx/wicket/test/common"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/stretchr/testify/require"
)

type ConsentTests struct {
	mockPipeline *integration_common.WicketPipeline
}

func newConsentTests() *ConsentTests {
	pipiline := integration_common.NewWicketPipeline()

	client1 := storage_models.NewClient()
	client1.ClientId = "client1"
	err := client1.SetAllowedGrantTypes(wicket.GrantTypesImplicit)
	if err != nil {
		panic(err)
	}
	client1.RequireConsent = false

	client1.AllowedScopes = []string{"openid", "profile"}
	client1.RedirectUris = []string{"https://client1/callback"}
	client1.AllowAccessTokensViaBrowser = true

	client2 := storage_models.NewClient()
	client2.ClientId = "client2"
	err = client2.SetAllowedGrantTypes(wicket.GrantTypesImplicit)
	if err != nil {
		panic(err)
	}
	client2.RequireConsent = true

	client2.AllowedScopes = []string{"openid", "profile", "api1", "api2"}
	client2.RedirectUris = []string{"https://client2/callback"}
	client2.AllowAccessTokensViaBrowser = true

	client3 := storage_models.NewClient()
	client3.ClientId = "client3"
	err = client3.SetAllowedGrantTypes(wicket.GrantTypesImplicit)
	if err != nil {
		panic(err)
	}
	client3.RequireConsent = false

	client3.AllowedScopes = []string{"openid", "profile", "api1", "api2"}
	client3.RedirectUris = []string{"https://client3/callback"}
	client3.AllowAccessTokensViaBrowser = true
	client3.IdentityProviderRestrictions = []string{"google"}

	pipiline.Clients = []*storage_models.Client{client1, client2, client3}

	pipiline.Users = append(pipiline.Users, test.NewTestUser())
	pipiline.Users[0].SubjectId = "bob"
	pipiline.Users[0].Username = "bob"
	pipiline.Users[0].Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(
			claimspkg.WithClaimType("name"), claimspkg.WithClaimValue("Bob Loblaw"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("email"), claimspkg.WithClaimValue("bob@loblaw.com"),
		),
		claimspkg.NewClaim(
			claimspkg.WithClaimType("role"), claimspkg.WithClaimValue("Attorney"),
		),
	}

	pipiline.IdentityScopes = append(pipiline.IdentityScopes, storage_models.IdentityResourcesOpenId())
	pipiline.IdentityScopes = append(pipiline.IdentityScopes, storage_models.IdentityResourcesProfile())
	pipiline.IdentityScopes = append(pipiline.IdentityScopes, storage_models.IdentityResourcesEmail())

	pipiline.ApiResources = append(pipiline.ApiResources, storage_models.NewApiResource())
	pipiline.ApiResources[0].Name = "api1"
	pipiline.ApiResources[0].Scopes = []string{"api1", "api2"}

	pipiline.ApiScopes = append(pipiline.ApiScopes, []*storage_models.ApiScope{
		storage_models.NewApiScope(),
		storage_models.NewApiScope(),
	}...)
	pipiline.ApiScopes[0].Name = "api1"
	pipiline.ApiScopes[1].Name = "api2"

	pipiline.Initialize()

	return &ConsentTests{
		mockPipeline: pipiline,
	}
}

func TestClient_requires_consent_should_show_consent_page(t *testing.T) {
	a := require.New(t)

	ti := newConsentTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client2",
			ResponseType: "id_token",
			Scope:        "openid",
			RedirectUri:  "https://client2/callback",
			State:        "123_state",
			Nonce:        "123_nonce",
		},
	)
	a.NoError(err)

	_, err = ti.mockPipeline.BrowserClient.Get(routePath.String())

	a.NoError(err)
	a.True(ti.mockPipeline.ConsentWasCalled)
}

func TestConsent_page_should_have_authorization_params(t *testing.T) {
	a := require.New(t)

	storeTypes := []string{"nil", "query_string", "distributed"}
	for _, storeType := range storeTypes {
		t.Run(storeType, func(t *testing.T) {
			ti := newConsentTests()

			switch storeType {
			case "nil":
			case "query_string":
				ti.mockPipeline.AuthorizationParametersMessageStore = test_common.NewQueryStringAuthorizationParametersMessageStore()

			case "distributed":
				// TODO:
			}

			user := models.NewLocalUser(models.WithLocalUserSubjectId("bob"))
			user.Tenant = "tenant_value"

			subject, err := user.CreatePrincipal()
			a.NoError(err)

			err = ti.mockPipeline.LoginWithPrincipal(subject)
			a.NoError(err)

			routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
				&integration_common.AuthorizeUrl{
					ClientId:     "client2",
					ResponseType: "id_token token",
					Scope:        "openid api1 api2",
					RedirectUri:  "https://client2/callback",
					State:        "123_state",
					Nonce:        "123_nonce",
					AcrValues:    "acr_1 acr_2 tenant:tenant_value",
					Extra: url.Values{
						"display":    []string{"popup"}, // must use a valid value form the spec for display
						"ui_locales": []string{"ui_locale_value"},
						"custom_foo": []string{"foo_value"},
					},
				},
			)
			a.NoError(err)

			_, err = ti.mockPipeline.BrowserClient.Get(routePath.String())
			a.NoError(err)

			consentRequest := ti.mockPipeline.ConsentRequest
			a.NotNil(consentRequest)
			a.Equal("client2", consentRequest.Client.ClientId)
			a.Equal("popup", consentRequest.DisplayMode)
			a.Equal("ui_locale_value", consentRequest.UiLocales)
			a.Equal("tenant_value", consentRequest.Tenant)
			a.ElementsMatch([]string{"acr_2", "acr_1"}, consentRequest.AcrValues)
			a.True(consentRequest.Parameters.Has("custom_foo"))
			a.Equal("foo_value", consentRequest.Parameters.Get("custom_foo"))
			a.ElementsMatch([]string{"api2", "openid", "api1"}, consentRequest.ValidatedResources.RawScopeValues())
		})
	}
}

func TestConsent_response_should_allow_successful_authorization_response(t *testing.T) {
	a := require.New(t)

	storeTypes := []string{"nil", "query_string", "distributed"}
	for _, storeType := range storeTypes {
		t.Run(storeType, func(t *testing.T) {
			ti := newConsentTests()

			switch storeType {
			case "nil":
			case "query_string":
				ti.mockPipeline.AuthorizationParametersMessageStore = test_common.NewQueryStringAuthorizationParametersMessageStore()

			case "distributed":
				// TODO:
			}

			err := ti.mockPipeline.Login("bob")
			a.NoError(err)

			ti.mockPipeline.ConsentResponse = models_messages.NewConsentResponse()
			ti.mockPipeline.ConsentResponse.ScopesValuesConsented = []string{"openid", "api2"}

			ti.mockPipeline.BrowserClient.StopRedirectingAfter = 2

			routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
				&integration_common.AuthorizeUrl{
					ClientId:     "client2",
					ResponseType: "id_token token",
					Scope:        "openid profile api1 api2",
					RedirectUri:  "https://client2/callback",
					State:        "123_state",
					Nonce:        "123_nonce",
				},
			)
			a.NoError(err)

			response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
			a.NoError(err)

			a.Equal(http.StatusFound, response.StatusCode)

			location := response.Header.Get("Location")
			a.True(strings.HasPrefix(location, "https://client2/callback"))

			u, err := url.Parse(location)
			a.NoError(err)

			fragments, _ := url.ParseQuery(u.Fragment)
			a.Empty(fragments.Get("error"))
			a.NotEmpty(fragments.Get("id_token"))
			a.Equal("123_state", fragments.Get("state"))
			scopes := strings.Split(fragments.Get("scope"), " ")
			a.ElementsMatch(scopes, []string{"api2", "openid"})
		})
	}
}

func TestConsent_response_should_reject_modified_request_params(t *testing.T) {
	a := require.New(t)

	ti := newConsentTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.ConsentResponse = models_messages.NewConsentResponse()
	ti.mockPipeline.ConsentResponse.ScopesValuesConsented = []string{"openid", "api2"}
	ti.mockPipeline.BrowserClient.AllowAutoRedirect = false

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client2",
			ResponseType: "id_token token",
			Scope:        "openid profile api2",
			RedirectUri:  "https://client2/callback",
			State:        "123_state",
			Nonce:        "123_nonce",
		},
	)
	a.NoError(err)

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	a.Equal(http.StatusFound, response.StatusCode)
	location := response.Header.Get("Location")
	a.True(strings.HasPrefix(location, ti.mockPipeline.TestServer.URL+"/consent"))

	response, err = ti.mockPipeline.BrowserClient.Get(location)
	a.NoError(err)

	a.Equal(http.StatusFound, response.StatusCode)
	location = response.Header.Get("Location")
	a.True(strings.HasPrefix(location, "/connect/authorize/callback"))

	modifiedAuthorizeCallback := ti.mockPipeline.TestServer.URL + location
	modifiedAuthorizeCallback = strings.Replace(modifiedAuthorizeCallback, "api2", "api1%20api2", -1)

	response, err = ti.mockPipeline.BrowserClient.Get(modifiedAuthorizeCallback)
	a.NoError(err)

	a.Equal(http.StatusFound, response.StatusCode)
	location = response.Header.Get("Location")
	a.True(strings.HasPrefix(location, ti.mockPipeline.TestServer.URL+"/consent"))

}

func TestConsent_response_missing_required_scopes_should_error(t *testing.T) {
	a := require.New(t)

	ti := newConsentTests()

	err := ti.mockPipeline.Login("bob")
	a.NoError(err)

	ti.mockPipeline.ConsentResponse = models_messages.NewConsentResponse()
	ti.mockPipeline.ConsentResponse.ScopesValuesConsented = []string{"api2"}
	ti.mockPipeline.BrowserClient.StopRedirectingAfter = 2

	routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
		&integration_common.AuthorizeUrl{
			ClientId:     "client2",
			ResponseType: "id_token token",
			Scope:        "openid profile api1 api2",
			RedirectUri:  "https://client2/callback",
			State:        "123_state",
			Nonce:        "123_nonce",
		},
	)
	a.NoError(err)

	response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	a.Equal(http.StatusFound, response.StatusCode)
	location := response.Header.Get("Location")
	a.True(strings.HasPrefix(location, "https://client2/callback"))

	u, err := url.Parse(location)
	a.NoError(err)

	fragments, _ := url.ParseQuery(u.Fragment)
	a.Equal("access_denied", fragments.Get("error"))
	a.Equal("123_state", fragments.Get("state"))

}

func TestConsent_response_of_temporarily_unavailable_should_return_error_to_client(t *testing.T) {
	a := require.New(t)

	storeTypes := []string{"nil", "query_string", "distributed"}
	for _, storeType := range storeTypes {
		t.Run(storeType, func(t *testing.T) {
			ti := newConsentTests()

			switch storeType {
			case "nil":
			case "query_string":
				ti.mockPipeline.AuthorizationParametersMessageStore = test_common.NewQueryStringAuthorizationParametersMessageStore()

			case "distributed":
				// TODO:
			}

			err := ti.mockPipeline.Login("bob")
			a.NoError(err)

			e := models_messages.TemporarilyUnavailable
			ti.mockPipeline.ConsentResponse = models_messages.NewConsentResponse()
			ti.mockPipeline.ConsentResponse.Error = &e
			ti.mockPipeline.ConsentResponse.ErrorDescription = "some description"

			ti.mockPipeline.BrowserClient.StopRedirectingAfter = 2

			routePath, err := ti.mockPipeline.CreateAuthorizeUrl(
				&integration_common.AuthorizeUrl{
					ClientId:     "client2",
					ResponseType: "id_token token",
					Scope:        "openid profile api1 api2",
					RedirectUri:  "https://client2/callback",
					State:        "123_state",
					Nonce:        "123_nonce",
				},
			)
			a.NoError(err)

			response, err := ti.mockPipeline.BrowserClient.Get(routePath.String())
			a.NoError(err)

			a.Equal(http.StatusFound, response.StatusCode)

			location := response.Header.Get("Location")
			a.True(strings.HasPrefix(location, "https://client2/callback"))

			u, err := url.Parse(location)
			a.NoError(err)

			fragments, _ := url.ParseQuery(u.Fragment)
			a.Equal("temporarily_unavailable", fragments.Get("error"))
			a.Equal("some description", fragments.Get("error_description"))
		})
	}
}
