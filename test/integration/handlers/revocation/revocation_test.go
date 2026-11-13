// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package revocation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	clientA = "revocation.client.a"
	clientB = "revocation.client.b"
	secret  = "secret"
)

func referenceClient(id string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id

	clientSecret := storage_models.NewSecret()
	clientSecret.Value = utils.Sha256(secret)
	client.ClientSecrets = []*storage_models.Secret{clientSecret}

	if err := client.SetAllowedGrantTypes(wicket.GrantTypesPassword); err != nil {
		panic(err)
	}
	client.AllowOfflineAccess = true
	client.AllowedScopes = []string{"api1"}
	return client
}

// revocationFixture is a pipeline whose reference token store the test can
// seed: the token endpoint issues JWT access tokens, so reference access
// tokens are placed in the store directly and read back through
// introspection.
type revocationFixture struct {
	*integration_common.WicketPipeline
	referenceTokens *storage_impl.ReferenceTokenStore
	handles         int
}

func newRevocationPipeline() *revocationFixture {
	pipeline := integration_common.NewWicketPipeline()
	referenceTokens := storage_impl.NewReferenceTokenStore()
	pipeline.Root.ServerConfig().SetReferenceTokenStore(referenceTokens)
	pipeline.Clients = append(pipeline.Clients, referenceClient(clientA), referenceClient(clientB))

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

	user := test.NewTestUser()
	user.SubjectId = "1"
	user.Username = "bob"
	user.Password = "bob"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.Initialize()
	return &revocationFixture{WicketPipeline: pipeline, referenceTokens: referenceTokens}
}

// storeReferenceToken places a reference access token for bob issued to
// clientId and returns its handle.
func (f *revocationFixture) storeReferenceToken(t *testing.T, clientId string) string {
	t.Helper()
	f.handles++
	// A handle carries no dot: the token validator reads a dotted value as a JWT.
	handle := fmt.Sprintf("reference-%s-%d", strings.ReplaceAll(clientId, ".", "-"), f.handles)
	token := &storage_models.Token{
		Issuer:          f.TestServer.URL,
		Audiences:       []string{"api1"},
		CreationTime:    time.Now().UTC(),
		Lifetime:        3600,
		Type:            wicket.TokenTypesAccessToken,
		ClientId:        clientId,
		AccessTokenType: wicket.AccessTokenTypeReference,
		Claims: []*claimspkg.Claim{
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesSubject), claimspkg.WithClaimValue("1")),
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesClientId), claimspkg.WithClaimValue(clientId)),
			claimspkg.NewClaim(claimspkg.WithClaimType(wicket.JwtClaimTypesScope), claimspkg.WithClaimValue("api1")),
		},
	}
	require.NoError(t, f.referenceTokens.StoreReferenceToken(context.Background(), handle, token))
	return handle
}

type tokenPair struct {
	jwt       string
	reference string
	refresh   string
}

func postToken(t *testing.T, pipeline *revocationFixture, form url.Values) (int, string) {
	t.Helper()
	response, err := pipeline.BackChannelClient.PostForm(pipeline.TestServer.URL+integration_common.TokenEndpoint, form)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

// issueTokens runs a password grant for bob and returns the client's refresh
// token together with a reference access token of the same subject and
// client.
func issueTokens(t *testing.T, pipeline *revocationFixture, clientId string) tokenPair {
	t.Helper()
	status, body := postToken(t, pipeline, url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientId},
		"client_secret": {secret},
		"scope":         {"api1 offline_access"},
		"username":      {"bob"},
		"password":      {"bob"},
	})
	require.Equal(t, http.StatusOK, status, "token endpoint: %s", body)
	pair := tokenPair{
		jwt:       gjson.Get(body, "access_token").String(),
		reference: pipeline.storeReferenceToken(t, clientId),
		refresh:   gjson.Get(body, "refresh_token").String(),
	}
	require.NotEmpty(t, pair.refresh)
	require.True(t, introspectActive(t, pipeline, pair.reference), "seeded reference token must start active")
	return pair
}

// exchangeRefresh redeems the refresh token at the token endpoint and returns
// the status and the OAuth error code, if any.
func exchangeRefresh(t *testing.T, pipeline *revocationFixture, clientId string, refresh string) (int, string) {
	t.Helper()
	status, body := postToken(t, pipeline, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientId},
		"client_secret": {secret},
		"refresh_token": {refresh},
	})
	return status, gjson.Get(body, "error").String()
}

func requireRefreshUsable(t *testing.T, pipeline *revocationFixture, clientId string, refresh string) {
	t.Helper()
	status, errorCode := exchangeRefresh(t, pipeline, clientId, refresh)
	require.Equal(t, http.StatusOK, status, "refresh exchange error %q", errorCode)
}

func requireRefreshRevoked(t *testing.T, pipeline *revocationFixture, clientId string, refresh string) {
	t.Helper()
	status, errorCode := exchangeRefresh(t, pipeline, clientId, refresh)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_grant", errorCode)
}

func introspectActive(t *testing.T, pipeline *revocationFixture, token string) bool {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, pipeline.TestServer.URL+integration_common.IntrospectionEndpoint, strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(t, err)
	request.SetBasicAuth("api1", secret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := pipeline.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "introspection: %s", body)
	return gjson.Get(string(body), "active").Bool()
}

type revocationCall struct {
	query       string
	form        url.Values
	basicClient string
	basicSecret string
	contentType string
}

type revocationAnswer struct {
	status int
	header http.Header
	body   string
}

func revoke(t *testing.T, pipeline *revocationFixture, call revocationCall) revocationAnswer {
	t.Helper()
	target := pipeline.TestServer.URL + integration_common.RevocationEndpoint + call.query
	request, err := http.NewRequest(http.MethodPost, target, strings.NewReader(call.form.Encode()))
	require.NoError(t, err)
	contentType := call.contentType
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	request.Header.Set("Content-Type", contentType)
	if call.basicClient != "" {
		request.SetBasicAuth(call.basicClient, call.basicSecret)
	}
	response, err := pipeline.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return revocationAnswer{status: response.StatusCode, header: response.Header, body: string(body)}
}

// revokeAs submits token in the body with the client's credentials in the
// body; an empty hint omits token_type_hint.
func revokeAs(t *testing.T, pipeline *revocationFixture, clientId string, token string, hint string) revocationAnswer {
	t.Helper()
	form := url.Values{"client_id": {clientId}, "client_secret": {secret}, "token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	return revoke(t, pipeline, revocationCall{form: form})
}

func requireRevocationOk(t *testing.T, answer revocationAnswer) {
	t.Helper()
	require.Equal(t, http.StatusOK, answer.status, "revocation: %s", answer.body)
	require.Empty(t, answer.body)
	cacheControl := strings.Join(answer.header.Values("Cache-Control"), ",")
	require.Contains(t, cacheControl, "no-store")
	require.Contains(t, cacheControl, "no-cache")
	require.Equal(t, "no-cache", answer.header.Get("Pragma"))
}

func requireRevocationError(t *testing.T, answer revocationAnswer, status int, errorCode string) {
	t.Helper()
	require.Equal(t, status, answer.status, "revocation: %s", answer.body)
	require.Equal(t, errorCode, gjson.Get(answer.body, "error").String(), "revocation: %s", answer.body)
}

func TestRevocationRequestShape(t *testing.T) {
	pipeline := newRevocationPipeline()

	t.Run("GET is not allowed", func(t *testing.T) {
		response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.RevocationEndpoint)
		require.NoError(t, err)
		_ = response.Body.Close()
		require.Equal(t, http.StatusMethodNotAllowed, response.StatusCode)
	})

	t.Run("JSON body is unsupported", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{contentType: "application/json", basicClient: clientA, basicSecret: secret})
		require.Equal(t, http.StatusUnsupportedMediaType, answer.status)
	})

	t.Run("empty body with header credentials is invalid_request", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{}, basicClient: clientA, basicSecret: secret})
		requireRevocationError(t, answer, http.StatusBadRequest, "invalid_request")
	})

	t.Run("missing token is invalid_request", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"client_id": {clientA}, "client_secret": {secret}}})
		requireRevocationError(t, answer, http.StatusBadRequest, "invalid_request")
	})

	t.Run("id_token hint is unsupported_token_type", func(t *testing.T) {
		answer := revokeAs(t, pipeline, clientA, "anything", "id_token")
		requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")
	})
}

func TestRevocationClientAuthentication(t *testing.T) {
	pipeline := newRevocationPipeline()

	t.Run("wrong secret in Basic header is 401 with a challenge", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {"anything"}}, basicClient: clientA, basicSecret: "wrong"})
		requireRevocationError(t, answer, http.StatusUnauthorized, "invalid_client")
		require.Equal(t, `Basic realm="wicket"`, answer.header.Get("WWW-Authenticate"))
		require.Equal(t, "application/json", answer.header.Get("Content-Type"))
	})

	t.Run("unknown client in body is 400", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"client_id": {"nobody"}, "client_secret": {secret}, "token": {"anything"}}})
		requireRevocationError(t, answer, http.StatusBadRequest, "invalid_client")
		require.Empty(t, answer.header.Get("WWW-Authenticate"))
	})

	t.Run("wrong secret in body is 400", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"client_id": {clientA}, "client_secret": {"wrong"}, "token": {"anything"}}})
		requireRevocationError(t, answer, http.StatusBadRequest, "invalid_client")
	})

	t.Run("no credentials is invalid_client", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {"anything"}}})
		requireRevocationError(t, answer, http.StatusBadRequest, "invalid_client")
	})

	t.Run("failed authentication leaves the token valid", func(t *testing.T) {
		tokens := issueTokens(t, pipeline, clientA)
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {tokens.refresh}}, basicClient: clientA, basicSecret: "wrong"})
		require.Equal(t, http.StatusUnauthorized, answer.status)
		requireRefreshUsable(t, pipeline, clientA, tokens.refresh)
	})
}

func TestRevocationUnknownTokenIsOk(t *testing.T) {
	pipeline := newRevocationPipeline()

	for _, hint := range []string{"", wicket.TokenTypeHintsAccessToken, wicket.TokenTypeHintsRefreshToken} {
		t.Run("hint "+hint, func(t *testing.T) {
			requireRevocationOk(t, revokeAs(t, pipeline, clientA, "does-not-exist", hint))
		})
	}

	t.Run("header credentials", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {"does-not-exist"}}, basicClient: clientA, basicSecret: secret})
		requireRevocationOk(t, answer)
	})
}

func TestRevocationOfRefreshToken(t *testing.T) {
	pipeline := newRevocationPipeline()

	for name, hint := range map[string]string{
		"without hint":            "",
		"with refresh_token hint": wicket.TokenTypeHintsRefreshToken,
	} {
		t.Run(name, func(t *testing.T) {
			tokens := issueTokens(t, pipeline, clientA)

			requireRevocationOk(t, revokeAs(t, pipeline, clientA, tokens.refresh, hint))

			require.False(t, introspectActive(t, pipeline, tokens.reference), "reference token of the same subject and client must be revoked")
			requireRefreshRevoked(t, pipeline, clientA, tokens.refresh)
		})
	}
}

func TestRevocationOfReferenceToken(t *testing.T) {
	pipeline := newRevocationPipeline()

	for name, hint := range map[string]string{
		"without hint":           "",
		"with access_token hint": wicket.TokenTypeHintsAccessToken,
	} {
		t.Run(name, func(t *testing.T) {
			tokens := issueTokens(t, pipeline, clientA)

			requireRevocationOk(t, revokeAs(t, pipeline, clientA, tokens.reference, hint))

			require.False(t, introspectActive(t, pipeline, tokens.reference))
		})
	}
}

func TestRevocationAcrossClientsIsSilent(t *testing.T) {
	pipeline := newRevocationPipeline()

	for name, tt := range map[string]struct {
		refresh bool
		hint    string
	}{
		"refresh token with refresh_token hint":  {refresh: true, hint: wicket.TokenTypeHintsRefreshToken},
		"reference token with access_token hint": {refresh: false, hint: wicket.TokenTypeHintsAccessToken},
		"refresh token without hint":             {refresh: true},
		"reference token without hint":           {refresh: false},
	} {
		t.Run(name, func(t *testing.T) {
			tokens := issueTokens(t, pipeline, clientA)
			target := tokens.reference
			if tt.refresh {
				target = tokens.refresh
			}

			requireRevocationOk(t, revokeAs(t, pipeline, clientB, target, tt.hint))

			require.True(t, introspectActive(t, pipeline, tokens.reference), "another client's revocation must not touch the reference token")
			requireRefreshUsable(t, pipeline, clientA, tokens.refresh)
		})
	}
}

// The token endpoint issues JWT access tokens, which carry no server-side
// state the revocation endpoint can remove: revoking one answers 200 and the
// token stays active. Update this test together with that behavior.
func TestRevocationKnownLimitationJwtAccessTokenStaysActive(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)
	require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")
	require.True(t, introspectActive(t, pipeline, tokens.jwt))

	requireRevocationOk(t, revokeAs(t, pipeline, clientA, tokens.jwt, wicket.TokenTypeHintsAccessToken))

	require.True(t, introspectActive(t, pipeline, tokens.jwt))
}

// The generator does not search the other token type when the hint names the
// wrong one; RFC 7009 §2.1 asks it to. Update this test together with that
// behavior.
func TestRevocationKnownDeviationMismatchedHintLeavesRefreshTokenValid(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)

	requireRevocationOk(t, revokeAs(t, pipeline, clientA, tokens.refresh, wicket.TokenTypeHintsAccessToken))

	requireRefreshUsable(t, pipeline, clientA, tokens.refresh)
}

func TestRevocationIgnoresQueryStringToken(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)

	answer := revoke(t, pipeline, revocationCall{
		query: "?" + url.Values{"token": {tokens.refresh}, "token_type_hint": {wicket.TokenTypeHintsRefreshToken}}.Encode(),
		form:  url.Values{"client_id": {clientA}, "client_secret": {secret}},
	})

	requireRevocationError(t, answer, http.StatusBadRequest, "invalid_request")
	require.True(t, introspectActive(t, pipeline, tokens.reference))
	requireRefreshUsable(t, pipeline, clientA, tokens.refresh)
}

func TestDiscoveryAdvertisesRevocationEndpoint(t *testing.T) {
	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()

	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.DiscoveryEndpoint)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	require.Equal(t, pipeline.TestServer.URL+"/connect/revocation", gjson.GetBytes(body, "revocation_endpoint").String())
}
