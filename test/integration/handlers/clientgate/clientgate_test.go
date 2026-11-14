// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package clientgate checks the client existence gate end to end: once a
// client is gone from the host's client store its outstanding grants and
// tokens stop working, and a failing client store is a server error rather
// than an invalid client or token.
package clientgate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	jwtClientId       = "gate.jwt"
	referenceClientId = "gate.reference"
	secret            = "secret"
	redirectUri       = "https://client.example/callback"
)

var errStoreDown = errors.New("client store unavailable")

// switchableClientStore is the host client store of these tests: clients can
// be removed, and the whole store can be switched to failing.
type switchableClientStore struct {
	mu      sync.Mutex
	clients map[string]*storage_models.Client
	failure error
}

func (s *switchableClientStore) FindClientById(_ context.Context, id string) (*storage_models.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return nil, s.failure
	}
	client, ok := s.clients[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return client, nil
}

func (s *switchableClientStore) FindClientsByAllowedOrigin(_ context.Context, origin string) ([]*storage_models.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failure != nil {
		return nil, s.failure
	}
	matches := []*storage_models.Client{}
	for _, client := range s.clients {
		for _, allowed := range client.AllowedCorsOrigins {
			if allowed == origin {
				matches = append(matches, client)
			}
		}
	}
	return matches, nil
}

func (s *switchableClientStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, id)
}

func (s *switchableClientStore) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = err
}

func gateClient(id string, tokenType wicket.AccessTokenType) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	client.AccessTokenType = tokenType

	clientSecret := storage_models.NewSecret()
	clientSecret.Value = utils.Sha256(secret)
	client.ClientSecrets = []*storage_models.Secret{clientSecret}

	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
		panic(err)
	}
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{wicket.StandardScopesOpenId, "api1"}
	client.RequirePkce = false
	client.RequireConsent = false
	client.RedirectUris = []string{redirectUri}
	return client
}

type fixture struct {
	*integration_common.WicketPipeline
	clients *switchableClientStore
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clients := &switchableClientStore{clients: map[string]*storage_models.Client{
		jwtClientId:       gateClient(jwtClientId, wicket.AccessTokenTypeJwt),
		referenceClientId: gateClient(referenceClientId, wicket.AccessTokenTypeReference),
	}}

	pipeline := integration_common.NewWicketPipeline()
	pipeline.ClientStore = clients
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	resource := storage_models.NewApiResource()
	resource.Name = "api1"
	apiSecret := storage_models.NewSecret()
	apiSecret.Value = utils.Sha256(secret)
	resource.ApiSecrets = []*storage_models.Secret{apiSecret}
	resource.Scopes = []string{"api1"}
	pipeline.ApiResources = append(pipeline.ApiResources, resource)

	scope := storage_models.NewApiScope()
	scope.Name = "api1"
	pipeline.ApiScopes = append(pipeline.ApiScopes, scope)

	bob := test.NewTestUser()
	bob.SubjectId = "1"
	bob.Username = "bob"
	bob.Password = "bob"
	pipeline.Users = append(pipeline.Users, bob)

	pipeline.Initialize()
	return &fixture{WicketPipeline: pipeline, clients: clients}
}

// authorize runs the authorize endpoint for clientId and returns the code.
func (f *fixture) authorize(t *testing.T, clientId string) string {
	t.Helper()
	require.NoError(t, f.Login("1"))
	authorization := f.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "code",
		Scope:        "openid api1 offline_access",
		RedirectUri:  redirectUri,
		State:        "123_state",
		Nonce:        "123_nonce",
	})
	require.NotNil(t, authorization)
	require.NotEmpty(t, authorization.Code())
	return authorization.Code()
}

func (f *fixture) post(t *testing.T, endpoint string, form url.Values, basic bool) (int, string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, f.TestServer.URL+endpoint, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		request.SetBasicAuth("api1", secret)
	}
	response, err := f.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

func codeForm(clientId string, code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectUri},
		"client_id":     {clientId},
		"client_secret": {secret},
	}
}

func refreshForm(clientId string, refreshToken string) url.Values {
	return url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientId},
		"client_secret": {secret},
	}
}

type issued struct {
	access  string
	refresh string
}

// issue runs the code flow for clientId and returns its tokens.
func (f *fixture) issue(t *testing.T, clientId string) issued {
	t.Helper()
	status, body := f.post(t, integration_common.TokenEndpoint, codeForm(clientId, f.authorize(t, clientId)), false)
	require.Equal(t, http.StatusOK, status, "token endpoint: %s", body)
	tokens := issued{access: gjson.Get(body, "access_token").String(), refresh: gjson.Get(body, "refresh_token").String()}
	require.NotEmpty(t, tokens.access)
	require.NotEmpty(t, tokens.refresh)
	return tokens
}

func (f *fixture) introspect(t *testing.T, token string) (int, string) {
	t.Helper()
	return f.post(t, integration_common.IntrospectionEndpoint, url.Values{"token": {token}}, true)
}

func requireInvalidClient(t *testing.T, status int, body string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	require.Equal(t, "invalid_client", gjson.Get(body, "error").String(), "body: %s", body)
}

func requireInactive(t *testing.T, status int, body string) {
	t.Helper()
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	require.JSONEq(t, `{"active":false}`, body)
}

func requireServerError(t *testing.T, status int, body string) {
	t.Helper()
	require.GreaterOrEqual(t, status, http.StatusInternalServerError, "body: %s", body)
	require.NotContains(t, body, "invalid_client")
	require.NotContains(t, body, "invalid_grant")
	require.NotContains(t, body, "active")
}

func TestRemovedClientLosesItsGrantsAndTokens(t *testing.T) {
	for _, clientId := range []string{jwtClientId, referenceClientId} {
		t.Run(clientId, func(t *testing.T) {
			f := newFixture(t)
			tokens := f.issue(t, clientId)
			pendingCode := f.authorize(t, clientId)

			status, body := f.introspect(t, tokens.access)
			require.Equal(t, http.StatusOK, status, "body: %s", body)
			require.True(t, gjson.Get(body, "active").Bool(), "token must be active before removal: %s", body)

			f.clients.remove(clientId)

			status, body = f.post(t, integration_common.TokenEndpoint, codeForm(clientId, pendingCode), false)
			requireInvalidClient(t, status, body)

			status, body = f.post(t, integration_common.TokenEndpoint, refreshForm(clientId, tokens.refresh), false)
			requireInvalidClient(t, status, body)

			status, body = f.introspect(t, tokens.access)
			requireInactive(t, status, body)
		})
	}
}

func TestFailingClientStoreIsAServerError(t *testing.T) {
	for _, clientId := range []string{jwtClientId, referenceClientId} {
		t.Run(clientId, func(t *testing.T) {
			f := newFixture(t)
			tokens := f.issue(t, clientId)
			pendingCode := f.authorize(t, clientId)

			f.clients.fail(errStoreDown)

			status, body := f.post(t, integration_common.TokenEndpoint, codeForm(clientId, pendingCode), false)
			requireServerError(t, status, body)

			status, body = f.post(t, integration_common.TokenEndpoint, refreshForm(clientId, tokens.refresh), false)
			requireServerError(t, status, body)

			status, body = f.introspect(t, tokens.access)
			requireServerError(t, status, body)

			// The failure consumed nothing: once the store recovers the same
			// refresh token still works.
			f.clients.fail(nil)
			status, body = f.post(t, integration_common.TokenEndpoint, refreshForm(clientId, tokens.refresh), false)
			require.Equal(t, http.StatusOK, status, "refresh after recovery: %s", body)
		})
	}
}
