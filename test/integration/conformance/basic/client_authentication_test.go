// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package basic

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

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

func addConformanceUser(pipeline *integration_common.WicketPipeline) {
	user := test.NewTestUser()
	user.SubjectId = "bob"
	user.Username = "bob"
	user.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(claimspkg.WithClaimType("name"), claimspkg.WithClaimValue("Bob Loblaw")),
	}
	pipeline.Users = append(pipeline.Users, user)
}

func newClientAuthenticationPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	client := storage_models.NewClient()
	client.Enabled = true
	client.ClientId = "code_pipeline.Client"

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
		"https://code_pipeline.Client/callback",
		"https://code_pipeline.Client/callback?foo=bar&baz=quux",
	}

	pipeline.Clients = []*storage_models.Client{client}

	addConformanceUser(pipeline)

	pipeline.Initialize()
	return pipeline
}

func authorizeForCode(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string, redirectUri string) (code string, authorizeResponse *http.Response) {
	t.Helper()

	pipeline.BrowserClient.AllowAutoRedirect = false
	routePath, err := pipeline.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "code",
		Scope:        "openid",
		RedirectUri:  redirectUri,
		Nonce:        "123_nonce",
	})
	require.NoError(t, err)

	response, err := pipeline.BrowserClient.Get(routePath.String())
	require.NoError(t, err)

	authorization := pipeline.ParseAuthorizationResponseUrl(response.Header.Get("Location"))
	require.NotEmpty(t, authorization.Code())
	return authorization.Code(), response
}

func redeemCode(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string, clientSecret string, code string, redirectUri string, credentialsInBody bool) (int, string) {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectUri)
	if credentialsInBody {
		form.Set("client_id", clientId)
		form.Set("client_secret", clientSecret)
	}

	request, err := http.NewRequest(http.MethodPost, pipeline.TestServer.URL+integration_common.TokenEndpoint, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if !credentialsInBody {
		request.SetBasicAuth(url.QueryEscape(clientId), url.QueryEscape(clientSecret))
	}

	response, err := pipeline.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

func assertSuccessfulTokenResponse(t *testing.T, status int, body string) {
	a := require.New(t)
	a.Equal(http.StatusOK, status, "token endpoint: %s", body)
	a.False(gjson.Get(body, "error").Exists())
	a.Equal("Bearer", gjson.Get(body, "token_type").String())
	a.NotEmpty(gjson.Get(body, "access_token").String())
	a.Greater(gjson.Get(body, "expires_in").Int(), int64(0))
	a.NotEmpty(gjson.Get(body, "id_token").String())
}

func TestTokenEndpointSupportsBasicAuthentication(t *testing.T) {
	a := require.New(t)

	pipeline := newClientAuthenticationPipeline()
	a.NoError(pipeline.Login("bob"))

	redirectUri := "https://code_pipeline.Client/callback?foo=bar&baz=quux"
	code, authorizeResponse := authorizeForCode(t, pipeline, "code_pipeline.Client", redirectUri)

	status, body := redeemCode(t, pipeline, "code_pipeline.Client", "secret", code, redirectUri, false)
	assertSuccessfulTokenResponse(t, status, body)

	cacheControl := strings.Join(authorizeResponse.Header.Values("Cache-Control"), ", ")
	a.Contains(cacheControl, "no-cache")
	a.Contains(cacheControl, "no-store")
}

func TestTokenEndpointSupportsFormEncodedAuthentication(t *testing.T) {
	a := require.New(t)

	pipeline := newClientAuthenticationPipeline()
	a.NoError(pipeline.Login("bob"))

	redirectUri := "https://code_pipeline.Client/callback?foo=bar&baz=quux"
	code, _ := authorizeForCode(t, pipeline, "code_pipeline.Client", redirectUri)

	status, body := redeemCode(t, pipeline, "code_pipeline.Client", "secret", code, redirectUri, true)
	assertSuccessfulTokenResponse(t, status, body)
}

// jwtPayload decodes a JWT's claims without verifying it.
func jwtPayload(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	require.GreaterOrEqual(t, len(parts), 2)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}
