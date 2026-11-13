// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package basic

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

func newResponseTypePipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	client := storage_models.NewClient()
	client.Enabled = true
	client.ClientId = "code_client"

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha512("secret")
	client.ClientSecrets = []*storage_models.Secret{secret}

	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{"openid"}
	client.RequireConsent = false
	client.RequirePkce = false
	client.RedirectUris = []string{"https://code_client/callback"}

	pipeline.Clients = append(pipeline.Clients, client)
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	addConformanceUser(pipeline)

	pipeline.Initialize()
	pipeline.BrowserClient.AllowAutoRedirect = false
	return pipeline
}

func TestResponseTypeCodeIsSupported(t *testing.T) {
	a := require.New(t)

	pipeline := newResponseTypePipeline()
	a.NoError(pipeline.Login("bob"))

	metadata, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.DiscoveryEndpoint)
	a.NoError(err)
	a.Equal(http.StatusOK, metadata.StatusCode)

	state := "123_state"

	routePath, err := pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     "code_client",
		ResponseType: "code",
		Scope:        "openid",
		RedirectUri:  "https://code_client/callback",
		State:        state,
		Nonce:        "123_nonce",
	})
	a.NoError(err)

	response, err := pipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	a.Equal(http.StatusFound, response.StatusCode)

	authorization := pipeline.ParseAuthorizationResponseUrl(response.Header.Get("Location"))
	a.NotNil(authorization)
	a.False(authorization.IsError())
	a.NotEmpty(authorization.Code())
	a.Equal(state, authorization.State())
}

func TestMissingResponseTypeIsRejected(t *testing.T) {
	a := require.New(t)

	pipeline := newResponseTypePipeline()
	a.NoError(pipeline.Login("bob"))

	routePath, err := pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:    "code_client",
		Scope:       "openid",
		RedirectUri: "https://code_client/callback",
		State:       "123_state",
		Nonce:       "123_nonce",
	})
	a.NoError(err)

	pipeline.BrowserClient.AllowAutoRedirect = true
	_, err = pipeline.BrowserClient.Get(routePath.String())
	a.NoError(err)

	a.True(pipeline.ErrorWasCalled)
	a.NotEmpty(pipeline.ErrorMessage.Error)
	a.Nil(pipeline.LoginRequest)
}
