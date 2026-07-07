// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package token

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const (
	client_id     = "client"
	client_secret = "secret"
	scope_name    = "api"
	scope_secret  = "api_secret"
)

type tokenTests struct {
	mockPipeline *integration_common.IdentityServerPipeline
}

func newTokenTests() *tokenTests {
	pipeline := integration_common.NewIdentityServerPipeline()

	client1 := storage_models.NewClient()
	client1.ClientId = client_id

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(client_secret)
	client1.ClientSecrets = []*storage_models.Secret{secret}

	_ = client1.SetAllowedGrantTypes([]string{gois.GrantTypeClientCredentials, gois.GrantTypePassword})

	client1.AllowedScopes = []string{"api"}

	pipeline.Clients = []*storage_models.Client{client1}

	pipeline.Users = append(pipeline.Users, test.NewTestUser())
	pipeline.Users[0].SubjectId = "bob"
	pipeline.Users[0].Username = "bob"
	pipeline.Users[0].Password = "password"
	pipeline.Users[0].Claims = []*claimspkg.Claim{
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

	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	pipeline.ApiResources = append(pipeline.ApiResources, storage_models.NewApiResource())
	pipeline.ApiResources[0].Name = "api1"
	pipeline.ApiResources[0].ApiSecrets = []*storage_models.Secret{secret}
	pipeline.ApiResources[0].Scopes = []string{scope_name}

	pipeline.ApiScopes = append(pipeline.ApiScopes, []*storage_models.ApiScope{
		storage_models.NewApiScope(),
	}...)
	pipeline.ApiScopes[0].Name = scope_name

	pipeline.Initialize()

	return &tokenTests{
		mockPipeline: pipeline,
	}
}
func TestClient_credentials_request_with_funny_headers_should_not_hang(t *testing.T) {
	a := require.New(t)

	ti := newTokenTests()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", client_id)
	data.Set("client_secret", client_secret)
	data.Set("scope", scope_name)

	req, err := http.NewRequest("POST", ti.mockPipeline.TestServer.URL+integration_common.TokenEndpoint, strings.NewReader(data.Encode()))
	a.NoError(err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "http://127.0.0.1:33086/appservice/appservice?t=1564165664142?load")

	response, err := ti.mockPipeline.BackChannelClient.Do(req)

	a.NoError(err)
	a.Equal(http.StatusOK, response.StatusCode)

	body, err := io.ReadAll(response.Body)
	a.NoError(err)
	result := string(body)
	error := gjson.Get(result, "error")
	a.False(error.Exists())
}

func TestResource_owner_request_with_funny_headers_should_not_hang(t *testing.T) {
	a := require.New(t)

	ti := newTokenTests()

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("username", "bob")
	data.Set("password", "password")
	data.Set("client_id", client_id)
	data.Set("client_secret", client_secret)
	data.Set("scope", scope_name)

	req, err := http.NewRequest("POST", ti.mockPipeline.TestServer.URL+integration_common.TokenEndpoint, strings.NewReader(data.Encode()))
	a.NoError(err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "http://127.0.0.1:33086/appservice/appservice?t=1564165664142?load")

	response, err := ti.mockPipeline.BackChannelClient.Do(req)

	a.NoError(err)
	a.Equal(http.StatusOK, response.StatusCode)

	body, err := io.ReadAll(response.Body)
	a.NoError(err)
	result := string(body)
	error := gjson.Get(result, "error")
	a.False(error.Exists())
}

func TestInvalid_form_post_text_values_should_return_400_error(t *testing.T) {
	a := require.New(t)

	ti := newTokenTests()

	text := fmt.Sprintf("grant_type=client_credentials&client_id={%s}&client_secret={%s}&scope=%%00", client_id, client_secret)

	req, err := http.NewRequest("POST", ti.mockPipeline.TestServer.URL+integration_common.TokenEndpoint, strings.NewReader(text))
	a.NoError(err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "http://127.0.0.1:33086/appservice/appservice?t=1564165664142?load")

	response, err := ti.mockPipeline.BackChannelClient.Do(req)

	a.NoError(err)
	a.Equal(http.StatusBadRequest, response.StatusCode)

	body, err := io.ReadAll(response.Body)
	a.NoError(err)
	result := string(body)
	error := gjson.Get(result, "error").String()
	a.Equal("invalid_request", error)
}
