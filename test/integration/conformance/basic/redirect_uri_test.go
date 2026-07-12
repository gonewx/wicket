// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package basic

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

func newRedirectUriPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	client := storage_models.NewClient()
	client.Enabled = true
	client.ClientId = "code_client"

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha512("secret")
	client.ClientSecrets = []*storage_models.Secret{secret}

	if err := client.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{"openid"}
	client.RequireConsent = false
	client.RequirePkce = false
	client.RedirectUris = []string{
		"https://code_client/callback",
		"https://code_client/callback?foo=bar&baz=quux",
	}

	pipeline.Clients = []*storage_models.Client{client}
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	addConformanceUser(pipeline)

	pipeline.Initialize()
	return pipeline
}

func TestRejectedRedirectUris(t *testing.T) {
	for name, redirectUri := range map[string]string{
		"unregistered redirect_uri":              "https://bad",
		"missing redirect_uri among multiple":    "",
		"query parameters in a different order":  "https://code_client/callback?baz=quux&foo=bar",
	} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			pipeline := newRedirectUriPipeline()
			a.NoError(pipeline.Login("bob"))

			routePath, err := pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
				ClientId:     "code_client",
				ResponseType: "code",
				Scope:        "openid",
				RedirectUri:  redirectUri,
				State:        "123_state",
				Nonce:        "123_nonce",
			})
			a.NoError(err)

			_, err = pipeline.BrowserClient.Get(routePath.String())
			a.NoError(err)

			a.True(pipeline.ErrorWasCalled)
			a.Equal("invalid_request", pipeline.ErrorMessage.Error)
		})
	}
}

func TestQueryParametersInTheRedirectUriArePreserved(t *testing.T) {
	a := require.New(t)

	pipeline := newRedirectUriPipeline()
	a.NoError(pipeline.Login("bob"))

	state := "123_state"

	pipeline.BrowserClient.AllowAutoRedirect = false
	routePath, err := pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     "code_client",
		ResponseType: "code",
		Scope:        "openid",
		RedirectUri:  "https://code_client/callback?foo=bar&baz=quux",
		State:        state,
		Nonce:        "123_nonce",
	})
	a.NoError(err)

	response, err := pipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	a.Equal(http.StatusFound, response.StatusCode)

	location := response.Header.Get("Location")
	a.True(strings.HasPrefix(location, "https://code_client/callback?"))

	authorization := pipeline.ParseAuthorizationResponseUrl(location)
	a.NotEmpty(authorization.Code())
	a.Equal(state, authorization.State())

	parsed, err := url.Parse(location)
	a.NoError(err)
	a.Equal("bar", parsed.Query().Get("foo"))
	a.Equal("quux", parsed.Query().Get("baz"))
}
