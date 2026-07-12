// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package pkce

import (
	"crypto/sha256"
	"encoding/base64"
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

const (
	redirectUri  = "https://code_client/callback"
	codeVerifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	clientSecret = "secret"
)

func pkceClient(id string, requirePkce bool, allowPlain bool) *storage_models.Client {
	client := storage_models.NewClient()
	client.Enabled = true
	client.ClientId = id

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(clientSecret)
	client.ClientSecrets = []*storage_models.Secret{secret}

	if err := client.SetAllowedGrantTypes(gois.GrantTypesCode); err != nil {
		panic(err)
	}
	client.RequirePkce = requirePkce
	client.AllowPlainTextPkce = allowPlain
	client.AllowedScopes = []string{"openid"}
	client.RequireConsent = false
	client.RedirectUris = []string{redirectUri}
	return client
}

func newPkcePipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	user := test.NewTestUser()
	user.SubjectId = "bob"
	user.Username = "bob"
	user.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(claimspkg.WithClaimType("name"), claimspkg.WithClaimValue("Bob Loblaw")),
	}
	pipeline.Users = append(pipeline.Users, user)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	pipeline.Clients = append(pipeline.Clients,
		pkceClient("code_client", true, false),
		pkceClient("code_client_optional", false, false),
		pkceClient("code_plain_client", true, true),
	)

	pipeline.Initialize()
	return pipeline
}

func sha256Challenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// requestAuthorization drives the authorize endpoint and returns the code (if
// issued); error-page dispatch is observable through the pipeline hooks.
func requestAuthorization(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string, challenge string, method string) string {
	t.Helper()

	pipeline.BrowserClient.AllowAutoRedirect = true
	authorization := pipeline.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId:            clientId,
		ResponseType:        "code",
		Scope:               "openid",
		RedirectUri:         redirectUri,
		Nonce:               "123_nonce",
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
	})
	if authorization == nil {
		return ""
	}
	return authorization.Code()
}

func redeemPkceCode(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string, code string, verifier string) (int, string) {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectUri)
	form.Set("client_id", clientId)
	form.Set("client_secret", clientSecret)
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}

	response, err := pipeline.BackChannelClient.PostForm(pipeline.TestServer.URL+integration_common.TokenEndpoint, form)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

func TestPlainChallengeMethodRequiresOptIn(t *testing.T) {
	t.Run("client without plain opt-in is rejected", func(t *testing.T) {
		a := require.New(t)

		pipeline := newPkcePipeline()
		a.NoError(pipeline.Login("bob"))

		requestAuthorization(t, pipeline, "code_client", codeVerifier, "plain")

		a.True(pipeline.ErrorWasCalled)
		a.Equal("invalid_request", pipeline.ErrorMessage.Error)
	})

	t.Run("client with plain opt-in completes the flow", func(t *testing.T) {
		a := require.New(t)

		pipeline := newPkcePipeline()
		a.NoError(pipeline.Login("bob"))

		code := requestAuthorization(t, pipeline, "code_plain_client", codeVerifier, "plain")
		a.NotEmpty(code)

		status, body := redeemPkceCode(t, pipeline, "code_plain_client", code, codeVerifier)
		a.Equal(http.StatusOK, status, body)
		a.Equal("Bearer", gjson.Get(body, "token_type").String())
		a.NotEmpty(gjson.Get(body, "access_token").String())
		a.NotEmpty(gjson.Get(body, "id_token").String())
	})
}

func TestSha256ChallengeMethodCompletesTheFlow(t *testing.T) {
	a := require.New(t)

	pipeline := newPkcePipeline()
	a.NoError(pipeline.Login("bob"))

	code := requestAuthorization(t, pipeline, "code_client", sha256Challenge(codeVerifier), "S256")
	a.NotEmpty(code)

	status, body := redeemPkceCode(t, pipeline, "code_client", code, codeVerifier)
	a.Equal(http.StatusOK, status, body)
	a.Equal("Bearer", gjson.Get(body, "token_type").String())
	a.NotEmpty(gjson.Get(body, "access_token").String())
	a.NotEmpty(gjson.Get(body, "id_token").String())
}

func TestAuthorizeRequestChallengeGuards(t *testing.T) {
	for name, tc := range map[string]struct {
		challenge string
		method    string
	}{
		"missing challenge for a pkce client": {challenge: "", method: ""},
		"challenge too short":                 {challenge: strings.Repeat("a", 42), method: "S256"},
		"challenge too long":                  {challenge: strings.Repeat("a", 129), method: "S256"},
		"unsupported challenge method":        {challenge: sha256Challenge(codeVerifier), method: "unknown_method"},
	} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			pipeline := newPkcePipeline()
			a.NoError(pipeline.Login("bob"))

			requestAuthorization(t, pipeline, "code_client", tc.challenge, tc.method)

			a.True(pipeline.ErrorWasCalled)
			a.Equal("invalid_request", pipeline.ErrorMessage.Error)
		})
	}
}

func TestTokenRequestVerifierGuards(t *testing.T) {
	for name, tc := range map[string]struct {
		verifier string
	}{
		"missing verifier":         {verifier: ""},
		"verifier too short":       {verifier: strings.Repeat("a", 42)},
		"verifier too long":        {verifier: strings.Repeat("a", 129)},
		"verifier does not match":  {verifier: strings.Repeat("b", 50)},
	} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			pipeline := newPkcePipeline()
			a.NoError(pipeline.Login("bob"))

			code := requestAuthorization(t, pipeline, "code_client", sha256Challenge(codeVerifier), "S256")
			a.NotEmpty(code)

			status, body := redeemPkceCode(t, pipeline, "code_client", code, tc.verifier)
			a.Equal(http.StatusBadRequest, status, body)
			a.Equal("invalid_grant", gjson.Get(body, "error").String())
		})
	}
}

func TestVerifierWithoutChallengeIsRejected(t *testing.T) {
	a := require.New(t)

	pipeline := newPkcePipeline()
	a.NoError(pipeline.Login("bob"))

	code := requestAuthorization(t, pipeline, "code_client_optional", "", "")
	a.NotEmpty(code)

	status, body := redeemPkceCode(t, pipeline, "code_client_optional", code, codeVerifier)
	a.Equal(http.StatusBadRequest, status, body)
	a.Equal("invalid_grant", gjson.Get(body, "error").String())
}
