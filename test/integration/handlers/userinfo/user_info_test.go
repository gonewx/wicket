// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package userinfo

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

func newUserInfoPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	client := storage_models.NewClient()
	client.ClientId = "ro.client"
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	client.ClientSecrets = []*storage_models.Secret{secret}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesPassword); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{"openid"}
	pipeline.Clients = append(pipeline.Clients, client)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	user := test.NewTestUser()
	user.SubjectId = "818727"
	user.Username = "alice"
	user.Password = "alice"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.Initialize()
	return pipeline
}

func passwordToken(t *testing.T, pipeline *integration_common.WicketPipeline) string {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "ro.client")
	form.Set("client_secret", "secret")
	form.Set("scope", "openid")
	form.Set("username", "alice")
	form.Set("password", "alice")

	response, err := pipeline.BackChannelClient.PostForm(pipeline.TestServer.URL+integration_common.TokenEndpoint, form)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "token endpoint: %s", body)

	token := gjson.GetBytes(body, "access_token").String()
	require.NotEmpty(t, token)
	return token
}

func TestUserInfoWithoutBearerTokenIsUnauthorized(t *testing.T) {
	a := require.New(t)

	pipeline := newUserInfoPipeline()

	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.UserInfoEndpoint)

	a.NoError(err)
	a.Equal(http.StatusUnauthorized, response.StatusCode)
}

func TestUserInfoAcceptsTokenViaPostForm(t *testing.T) {
	a := require.New(t)

	pipeline := newUserInfoPipeline()
	token := passwordToken(t, pipeline)

	form := url.Values{}
	form.Set("access_token", token)
	response, err := pipeline.BackChannelClient.Post(
		pipeline.TestServer.URL+integration_common.UserInfoEndpoint,
		"application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()),
	)

	a.NoError(err)
	a.Equal(http.StatusOK, response.StatusCode)

	body, err := io.ReadAll(response.Body)
	a.NoError(err)
	_ = response.Body.Close()
	a.Equal("818727", gjson.GetBytes(body, "sub").String())
}

func TestUserInfoRejectsUnsupportedMethod(t *testing.T) {
	a := require.New(t)

	pipeline := newUserInfoPipeline()
	token := passwordToken(t, pipeline)

	request, err := http.NewRequest(http.MethodPut, pipeline.TestServer.URL+integration_common.UserInfoEndpoint, nil)
	a.NoError(err)
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := pipeline.BackChannelClient.Do(request)

	a.NoError(err)
	a.Equal(http.StatusMethodNotAllowed, response.StatusCode)
}
