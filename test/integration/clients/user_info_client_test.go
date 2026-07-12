// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package clients

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket/server"
	test_setup "github.com/gonewx/wicket/test/integration/clients/setup"
)

type testUserInfoEndpointClient struct {
	TokenEndpoint    string
	UserInfoEndpoint string
	client           *http.Client
}

func NewTestUserInfoEndpointClient(t *testing.T) *testUserInfoEndpointClient {
	testSrv := test_setup.ConfigureServices(server.DefaultLogger())
	t.Cleanup(testSrv.Close)
	return &testUserInfoEndpointClient{
		TokenEndpoint:    testSrv.URL + "/connect/token",
		UserInfoEndpoint: testSrv.URL + "/connect/userinfo",
		client:           testSrv.Client(),
	}
}

type passwordTokenResponse struct {
	status int
	raw    string
}

func (r *passwordTokenResponse) IsError() bool {
	return r.status != http.StatusOK || gjson.Get(r.raw, "error").Exists()
}

func (r *passwordTokenResponse) AccessToken() string {
	return gjson.Get(r.raw, "access_token").String()
}

func (ts *testUserInfoEndpointClient) requestPasswordToken(t *testing.T, scope string) *passwordTokenResponse {
	t.Helper()

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", "roclient")
	data.Set("client_secret", "secret")
	data.Set("scope", scope)
	data.Set("username", "bob")
	data.Set("password", "bob")

	response, err := ts.client.PostForm(ts.TokenEndpoint, data)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()

	return &passwordTokenResponse{status: response.StatusCode, raw: string(body)}
}

type userInfoResponse struct {
	status int
	Raw    string
}

func (r *userInfoResponse) IsError() bool {
	return r.status != http.StatusOK
}

func (ts *testUserInfoEndpointClient) getUserInfo(t *testing.T, token string) *userInfoResponse {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, ts.UserInfoEndpoint, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	response, err := ts.client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()

	return &userInfoResponse{status: response.StatusCode, Raw: string(body)}
}

func TestValid_client_with_GET_should_succeed(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	response := ts.requestPasswordToken(t, "openid email api1")
	a.False(response.IsError())

	userInfo := ts.getUserInfo(t, response.AccessToken())

	a.False(userInfo.IsError())

	claims := gjson.Parse(userInfo.Raw).Map()
	a.Len(claims, 3)
	a.Equal("88421113", claims["sub"].String())
	a.Equal("BobSmith@email.com", claims["email"].String())
	a.True(claims["email_verified"].Bool())
}

func TestRequest_address_scope_should_return_expected_response(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	response := ts.requestPasswordToken(t, "openid address")
	a.False(response.IsError())

	userInfo := ts.getUserInfo(t, response.AccessToken())

	a.False(userInfo.IsError())
	a.Greater(len(gjson.Parse(userInfo.Raw).Map()), 0)

	a.Equal("{ 'street_address': 'One Hacker Way', 'locality': 'Heidelberg', 'postal_code': 69118, 'country': 'Germany' }", gjson.Get(userInfo.Raw, "address").String())
}

func TestUsing_a_token_with_no_identity_scope_should_fail(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	response := ts.requestPasswordToken(t, "api1")
	a.False(response.IsError())

	userInfo := ts.getUserInfo(t, response.AccessToken())

	a.True(userInfo.IsError())
	a.Equal(http.StatusForbidden, userInfo.status)
}

func TestUsing_a_token_with_an_identity_scope_but_no_openid_should_fail(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	response := ts.requestPasswordToken(t, "email api1")
	a.False(response.IsError())

	userInfo := ts.getUserInfo(t, response.AccessToken())

	a.True(userInfo.IsError())
	a.Equal(http.StatusForbidden, userInfo.status)
}

func TestInvalid_token_should_fail(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	userInfo := ts.getUserInfo(t, "invalid")

	a.True(userInfo.IsError())
	a.Equal(http.StatusUnauthorized, userInfo.status)
}

func TestComplex_json_should_be_correct(t *testing.T) {
	a := require.New(t)

	ts := NewTestUserInfoEndpointClient(t)

	response := ts.requestPasswordToken(t, "openid email api1 api4.with.roles roles")
	a.False(response.IsError())

	payload := getPayload(response)

	scopes := payload["scope"]
	a.Len(scopes, 5)
	a.Contains(scopes, "openid")
	a.Contains(scopes, "email")
	a.Contains(scopes, "api1")
	a.Contains(scopes, "api4.with.roles")
	a.Contains(scopes, "roles")

	userInfo := ts.getUserInfo(t, response.AccessToken())

	a.False(userInfo.IsError())

	roles := gjson.Get(userInfo.Raw, "role")
	a.True(roles.IsArray())
	a.Len(roles.Array(), 2)

	roleValues := make([]string, 0, 2)
	for _, role := range roles.Array() {
		roleValues = append(roleValues, role.String())
	}
	a.Contains(roleValues, "Geek")
	a.Contains(roleValues, "Developer")
}

func getPayload(response *passwordTokenResponse) map[string]any {
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
