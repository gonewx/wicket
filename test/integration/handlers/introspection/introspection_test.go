// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package introspection

import (
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

func clientCredentialsClient(id string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	client.ClientSecrets = []*storage_models.Secret{secret}

	if err := client.SetAllowedGrantTypes(gois.GrantTypesClientCredentials); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{"api1", "api2", "api3-a", "api3-b"}
	return client
}

func namedApiResource(name string, scopes []string) *storage_models.ApiResource {
	resource := storage_models.NewApiResource()
	resource.Name = name

	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	resource.ApiSecrets = []*storage_models.Secret{secret}
	resource.Scopes = scopes
	return resource
}

func newIntrospectionPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	passwordClient := storage_models.NewClient()
	passwordClient.ClientId = "ro.client"
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256("secret")
	passwordClient.ClientSecrets = []*storage_models.Secret{secret}
	if err := passwordClient.SetAllowedGrantTypes(gois.GrantTypesPassword); err != nil {
		panic(err)
	}
	passwordClient.AllowedScopes = []string{"api1", "api2", "api3-a", "api3-b"}

	pipeline.Clients = append(pipeline.Clients,
		clientCredentialsClient("client1"),
		clientCredentialsClient("client2"),
		clientCredentialsClient("client3"),
		passwordClient,
	)

	pipeline.ApiResources = append(pipeline.ApiResources,
		namedApiResource("api1", []string{"api1"}),
		namedApiResource("api2", []string{"api2"}),
		namedApiResource("api3", []string{"api3-a", "api3-b"}),
	)

	for _, name := range []string{"api1", "api2", "api3-a", "api3-b"} {
		scope := storage_models.NewApiScope()
		scope.Name = name
		pipeline.ApiScopes = append(pipeline.ApiScopes, scope)
	}

	user := test.NewTestUser()
	user.SubjectId = "1"
	user.Username = "bob"
	user.Password = "bob"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.Initialize()
	return pipeline
}

func requestToken(t *testing.T, pipeline *integration_common.WicketPipeline, form url.Values) string {
	t.Helper()

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

func clientCredentialsToken(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string, scope string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientId)
	form.Set("client_secret", "secret")
	form.Set("scope", scope)
	return requestToken(t, pipeline, form)
}

func introspect(t *testing.T, pipeline *integration_common.WicketPipeline, api string, apiSecret string, form url.Values) (*http.Response, string) {
	t.Helper()

	request, err := http.NewRequest(http.MethodPost, pipeline.TestServer.URL+integration_common.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	if api != "" {
		request.SetBasicAuth(api, apiSecret)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := pipeline.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response, string(body)
}


// audienceValues normalizes the aud member: RFC 7519 permits both the single
// string and the array form for one audience; wicket serializes uniformly as
// an array.
func audienceValues(body string) []string {
	aud := gjson.Get(body, "aud")
	if aud.IsArray() {
		values := make([]string, 0)
		for _, entry := range aud.Array() {
			values = append(values, entry.String())
		}
		return values
	}
	return []string{aud.String()}
}

func scopeValues(body string) []string {
	return strings.Fields(gjson.Get(body, "scope").String())
}

func TestIntrospectionAuthenticationGuards(t *testing.T) {
	for name, tc := range map[string]struct {
		api        string
		apiSecret  string
		token      string
		wantStatus int
	}{
		"empty request without authentication is unauthorized": {
			wantStatus: http.StatusUnauthorized,
		},
		"unknown api is unauthorized": {
			api:        "unknown",
			apiSecret:  "invalid",
			wantStatus: http.StatusUnauthorized,
		},
		"wrong api secret is unauthorized": {
			api:        "api1",
			apiSecret:  "invalid",
			wantStatus: http.StatusUnauthorized,
		},
		"authenticated request without a token is a bad request": {
			api:        "api1",
			apiSecret:  "secret",
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)
			pipeline := newIntrospectionPipeline()

			form := url.Values{}
			if tc.token != "" {
				form.Set("token", tc.token)
			}
			response, _ := introspect(t, pipeline, tc.api, tc.apiSecret, form)
			a.Equal(tc.wantStatus, response.StatusCode)
		})
	}
}

func TestIntrospectionRejectsNonFormContent(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()
	token := clientCredentialsToken(t, pipeline, "client1", "api1")

	payload, err := json.Marshal(map[string]string{"token": token})
	a.NoError(err)

	request, err := http.NewRequest(http.MethodPost, pipeline.TestServer.URL+integration_common.IntrospectionEndpoint, strings.NewReader(string(payload)))
	a.NoError(err)
	request.SetBasicAuth("api1", "secret")
	request.Header.Set("Content-Type", "application/json")

	response, err := pipeline.BackChannelClient.Do(request)
	a.NoError(err)
	a.Equal(http.StatusUnsupportedMediaType, response.StatusCode)
}

func TestIntrospectionInvalidTokenIsInactive(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()

	form := url.Values{}
	form.Set("token", "invalid")
	response, body := introspect(t, pipeline, "api1", "secret", form)

	a.Equal(http.StatusOK, response.StatusCode)
	a.False(gjson.Get(body, "active").Bool())
}

func TestIntrospectionValidTokenResponseShape(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()
	token := clientCredentialsToken(t, pipeline, "client1", "api1")

	form := url.Values{}
	form.Set("token", token)
	response, body := introspect(t, pipeline, "api1", "secret", form)

	a.Equal(http.StatusOK, response.StatusCode)

	values := gjson.Parse(body)
	a.Equal(gjson.String, values.Get("iss").Type)
	a.Equal([]string{"api1"}, audienceValues(body))
	a.Equal(gjson.Number, values.Get("nbf").Type)
	a.Equal(gjson.Number, values.Get("exp").Type)
	a.Equal(gjson.String, values.Get("client_id").Type)
	a.Equal(gjson.True, values.Get("active").Type)
	a.Equal("api1", values.Get("scope").String())
}

func TestIntrospectionPasswordGrantTokenResponseShape(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "ro.client")
	form.Set("client_secret", "secret")
	form.Set("scope", "api1")
	form.Set("username", "bob")
	form.Set("password", "bob")
	token := requestToken(t, pipeline, form)

	introspectForm := url.Values{}
	introspectForm.Set("token", token)
	response, body := introspect(t, pipeline, "api1", "secret", introspectForm)

	a.Equal(http.StatusOK, response.StatusCode)

	values := gjson.Parse(body)
	a.Equal(gjson.String, values.Get("iss").Type)
	a.Equal([]string{"api1"}, audienceValues(body))
	a.Equal(gjson.Number, values.Get("nbf").Type)
	a.Equal(gjson.Number, values.Get("exp").Type)
	a.Equal(gjson.String, values.Get("client_id").Type)
	a.Equal(gjson.True, values.Get("active").Type)
	a.Equal("api1", values.Get("scope").String())
}

func TestIntrospectionMultipleScopesMultipleAudiences(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()
	token := clientCredentialsToken(t, pipeline, "client1", "api2 api3-a api3-b")

	form := url.Values{}
	form.Set("token", token)
	response, body := introspect(t, pipeline, "api3", "secret", form)

	a.Equal(http.StatusOK, response.StatusCode)

	values := gjson.Parse(body)
	a.True(values.Get("aud").IsArray())
	for _, aud := range values.Get("aud").Array() {
		a.Equal(gjson.String, aud.Type)
	}
	a.Equal(gjson.True, values.Get("active").Type)
	a.ElementsMatch([]string{"api3-a", "api3-b"}, scopeValues(body))
}

func TestIntrospectionMultipleScopesSingleAudience(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()
	token := clientCredentialsToken(t, pipeline, "client1", "api3-a api3-b")

	form := url.Values{}
	form.Set("token", token)
	response, body := introspect(t, pipeline, "api3", "secret", form)

	a.Equal(http.StatusOK, response.StatusCode)

	values := gjson.Parse(body)
	a.Equal([]string{"api3"}, audienceValues(body))
	a.Equal(gjson.True, values.Get("active").Type)
	a.ElementsMatch([]string{"api3-a", "api3-b"}, scopeValues(body))
}

func TestIntrospectionApiSeesOnlyItsOwnScopes(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()
	token := clientCredentialsToken(t, pipeline, "client3", "api1 api2 api3-a")

	form := url.Values{}
	form.Set("token", token)
	response, body := introspect(t, pipeline, "api3", "secret", form)

	a.Equal(http.StatusOK, response.StatusCode)
	a.True(gjson.Get(body, "active").Bool())
	a.Equal([]string{"api3-a"}, scopeValues(body))
}

func TestIntrospectionValidTokenWithMultipleOwnScopes(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()
	token := clientCredentialsToken(t, pipeline, "client1", "api1 api2")

	form := url.Values{}
	form.Set("token", token)
	response, body := introspect(t, pipeline, "api1", "secret", form)

	a.Equal(http.StatusOK, response.StatusCode)
	a.True(gjson.Get(body, "active").Bool())
	a.Equal([]string{"api1"}, scopeValues(body))
}

func TestIntrospectionForeignScopeTokenIsInactive(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()
	token := clientCredentialsToken(t, pipeline, "client1", "api1")

	form := url.Values{}
	form.Set("token", token)
	response, body := introspect(t, pipeline, "api2", "secret", form)

	a.Equal(http.StatusOK, response.StatusCode)
	a.False(gjson.Get(body, "active").Bool())
}

func TestIntrospectionClaimShapeForUserToken(t *testing.T) {
	a := require.New(t)

	pipeline := newIntrospectionPipeline()

	user := pipeline.Users[0]
	user.Claims = append(user.Claims, claimspkg.NewClaim(
		claimspkg.WithClaimType("name"), claimspkg.WithClaimValue("Bob Loblaw"),
	))

	token := clientCredentialsToken(t, pipeline, "client1", "api1")

	form := url.Values{}
	form.Set("token", token)
	_, body := introspect(t, pipeline, "api1", "secret", form)

	a.True(gjson.Get(body, "active").Bool())
	a.Equal("client1", gjson.Get(body, "client_id").String())
}
