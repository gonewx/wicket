// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package clients

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	claimspkg "github.com/gonewx/wicket/claims"
	client_messages "github.com/gonewx/wicket/client/messages"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/server"
	test_setup "github.com/gonewx/wicket/test/integration/clients/setup"
	"github.com/gonewx/wicket/utils"
)

type testUserInfoEndpointClient struct {
	TokenEndpoint    string
	UserInfoEndpoint string
	client           *http.Client
}

func NewTestUserInfoEndpointClient(t *testing.T) *testUserInfoEndpointClient {
	testSrv := test_setup.ConfigureServices(server.DefaultLogger())
	return &testUserInfoEndpointClient{
		TokenEndpoint:    testSrv.URL + "/connect/token",
		UserInfoEndpoint: testSrv.URL + "/connect/userinfo",
		client:           testSrv.Client(),
	}
}

func TestValid_client_with_GET_should_succeed(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	req := client_messages.NewPasswordTokenRequest()
	req.Address = ts.TokenEndpoint
	req.ClientId = "roclient"
	req.ClientSecret = "secret"

	req.Scope = "openid email api1"
	req.UserName = "bob"
	req.Password = "bob"

	response, err := extensions.RequestPasswordToken(ts.client, req)
	a.NoError(err)

	a.False(response.IsError())

	userInfoRequest := client_messages.NewUserInfoRequest()
	userInfoRequest.Address = ts.UserInfoEndpoint
	userInfoRequest.Token = response.AccessToken()

	userInfo, err := extensions.GetUserInfo(ts.client, userInfoRequest)
	a.NoError(err)

	a.False(userInfo.IsError())
	a.Len(userInfo.Claims, 3)

	a.True(utils.AnyPred(userInfo.Claims, func(c *claimspkg.Claim) bool {
		return c.Type == "sub" && c.Value == "88421113"
	}))

	a.True(utils.AnyPred(userInfo.Claims, func(c *claimspkg.Claim) bool {
		return c.Type == "email" && c.Value == "BobSmith@email.com"
	}))

	a.True(utils.AnyPred(userInfo.Claims, func(c *claimspkg.Claim) bool {
		return c.Type == "email_verified" && c.Value == true
	}))
}
func TestRequest_address_scope_should_return_expected_response(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	req := client_messages.NewPasswordTokenRequest()
	req.Address = ts.TokenEndpoint
	req.ClientId = "roclient"
	req.ClientSecret = "secret"

	req.Scope = "openid address"
	req.UserName = "bob"
	req.Password = "bob"

	response, err := extensions.RequestPasswordToken(ts.client, req)
	a.NoError(err)

	a.False(response.IsError())

	userInfoRequest := client_messages.NewUserInfoRequest()
	userInfoRequest.Address = ts.UserInfoEndpoint
	userInfoRequest.Token = response.AccessToken()

	userInfo, err := extensions.GetUserInfo(ts.client, userInfoRequest)
	a.NoError(err)

	a.False(userInfo.IsError())
	a.Greater(len(userInfo.Claims), 0)

	a.Equal("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }", userInfo.Claims[0].Value)
}

func TestUsing_a_token_with_no_identity_scope_should_fail(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	req := client_messages.NewPasswordTokenRequest()
	req.Address = ts.TokenEndpoint
	req.ClientId = "roclient"
	req.ClientSecret = "secret"

	req.Scope = "api1"
	req.UserName = "bob"
	req.Password = "bob"

	response, err := extensions.RequestPasswordToken(ts.client, req)
	a.NoError(err)

	a.False(response.IsError())

	userInfoRequest := client_messages.NewUserInfoRequest()
	userInfoRequest.Address = ts.UserInfoEndpoint
	userInfoRequest.Token = response.AccessToken()

	userInfo, err := extensions.GetUserInfo(ts.client, userInfoRequest)
	a.NoError(err)

	a.True(userInfo.IsError())
	a.Equal(http.StatusForbidden, userInfo.HttpResponse.StatusCode)
}

func TestUsing_a_token_with_an_identity_scope_but_no_openid_should_fail(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	req := client_messages.NewPasswordTokenRequest()
	req.Address = ts.TokenEndpoint
	req.ClientId = "roclient"
	req.ClientSecret = "secret"

	req.Scope = "email api1"
	req.UserName = "bob"
	req.Password = "bob"

	response, err := extensions.RequestPasswordToken(ts.client, req)
	a.NoError(err)

	a.False(response.IsError())

	userInfoRequest := client_messages.NewUserInfoRequest()
	userInfoRequest.Address = ts.UserInfoEndpoint
	userInfoRequest.Token = response.AccessToken()

	userInfo, err := extensions.GetUserInfo(ts.client, userInfoRequest)
	a.NoError(err)

	a.True(userInfo.IsError())
	a.Equal(http.StatusForbidden, userInfo.HttpResponse.StatusCode)
}

func TestInvalid_token_should_fail(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	userInfoRequest := client_messages.NewUserInfoRequest()
	userInfoRequest.Address = ts.UserInfoEndpoint
	userInfoRequest.Token = "invalid"

	userInfo, err := extensions.GetUserInfo(ts.client, userInfoRequest)
	a.NoError(err)

	a.True(userInfo.IsError())
	a.Equal(http.StatusUnauthorized, userInfo.HttpResponse.StatusCode)
}

func TestComplex_json_should_be_correct(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	req := client_messages.NewPasswordTokenRequest()
	req.Address = ts.TokenEndpoint
	req.ClientId = "roclient"
	req.ClientSecret = "secret"

	req.Scope = "openid email api1 api4.with.roles roles"
	req.UserName = "bob"
	req.Password = "bob"

	response, err := extensions.RequestPasswordToken(ts.client, req)
	a.NoError(err)

	a.False(response.IsError())

	payload := getPayload(response)

	scopes := payload["scope"]
	a.Len(scopes, 5)
	a.Contains(scopes, "openid")
	a.Contains(scopes, "email")
	a.Contains(scopes, "api1")
	a.Contains(scopes, "api4.with.roles")
	a.Contains(scopes, "roles")

	userInfoRequest := client_messages.NewUserInfoRequest()
	userInfoRequest.Address = ts.UserInfoEndpoint
	userInfoRequest.Token = response.AccessToken()

	userInfo, err := extensions.GetUserInfo(ts.client, userInfoRequest)
	a.NoError(err)

	a.False(userInfo.IsError())

	roles := gjson.Get(userInfo.Raw, "role")
	a.True(roles.IsArray())
	a.Len(roles.Array(), 2)

	a.True(utils.AnyPred(roles.Array(), func(r gjson.Result) bool {
		return r.String() == "Geek"
	}))
	a.True(utils.AnyPred(roles.Array(), func(r gjson.Result) bool {
		return r.String() == "Developer"
	}))
}

func getPayload(response *client_messages.TokenResponse) map[string]any {
	dict := make(map[string]any, 0)

	token := strings.Split(response.AccessToken(), ".")
	if len(token) < 2 {
		return dict
	}

	payload, err := base64.RawURLEncoding.DecodeString(token[1])
	if err != nil {
		return dict
	}

	if err := json.Unmarshal(payload, &dict); err != nil {
		return dict
	}

	return dict
}
