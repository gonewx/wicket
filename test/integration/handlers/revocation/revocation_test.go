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
	f.storeReferenceTokenUnder(t, clientId, handle)
	return handle
}

// storeReferenceTokenUnder places a reference access token for bob issued to
// clientId under the given handle.
func (f *revocationFixture) storeReferenceTokenUnder(t *testing.T, clientId string, handle string) {
	t.Helper()
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
// state the revocation endpoint can remove: the endpoint refuses one with 400
// unsupported_token_type and the token stays valid until it expires. Update
// this test together with that behavior.
func TestRevocationKnownLimitationJwtAccessTokenStaysActive(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)
	require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")
	require.True(t, introspectActive(t, pipeline, tokens.jwt))

	answer := revokeAs(t, pipeline, clientA, tokens.jwt, wicket.TokenTypeHintsAccessToken)
	requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")

	require.True(t, introspectActive(t, pipeline, tokens.jwt))
}

// The hint plays no part in refusing a JWT access token: without a hint, and
// with a hint naming a refresh token, the answer is the same.
func TestRevocationRejectsJwtAccessTokenWhateverTheHint(t *testing.T) {
	pipeline := newRevocationPipeline()

	for name, hint := range map[string]string{
		"without hint":            "",
		"with refresh_token hint": wicket.TokenTypeHintsRefreshToken,
	} {
		t.Run(name, func(t *testing.T) {
			tokens := issueTokens(t, pipeline, clientA)
			require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")
			require.True(t, introspectActive(t, pipeline, tokens.jwt))

			answer := revokeAs(t, pipeline, clientA, tokens.jwt, hint)
			requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")

			require.True(t, introspectActive(t, pipeline, tokens.jwt))
		})
	}
}

// Another client's JWT access token gets the same answer as the client's own:
// the answer does not tell whose token it is.
func TestRevocationRejectsAnotherClientsJwtAccessToken(t *testing.T) {
	pipeline := newRevocationPipeline()

	for name, hint := range map[string]string{
		"with access_token hint": wicket.TokenTypeHintsAccessToken,
		"without hint":           "",
	} {
		t.Run(name, func(t *testing.T) {
			tokens := issueTokens(t, pipeline, clientA)
			require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")

			answer := revokeAs(t, pipeline, clientB, tokens.jwt, hint)
			requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")

			require.True(t, introspectActive(t, pipeline, tokens.jwt))
		})
	}
}

// A dotted value that is not a valid JWT access token is refused like a valid
// one: the endpoint does not verify what it is handed.
func TestRevocationRejectsInvalidJwtShapedTokens(t *testing.T) {
	pipeline := newRevocationPipeline()

	t.Run("JWT with a broken signature", func(t *testing.T) {
		tokens := issueTokens(t, pipeline, clientA)
		segments := strings.Split(tokens.jwt, ".")
		require.Len(t, segments, 3, "token endpoint must issue a compact JWT")
		require.NotEmpty(t, segments[2])
		replacement := "A"
		if strings.HasPrefix(segments[2], "A") {
			replacement = "B"
		}
		segments[2] = replacement + segments[2][1:]
		broken := strings.Join(segments, ".")
		require.NotEqual(t, tokens.jwt, broken)
		require.False(t, introspectActive(t, pipeline, broken), "a JWT with a broken signature must not be active")

		answer := revokeAs(t, pipeline, clientA, broken, wicket.TokenTypeHintsAccessToken)
		requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")
	})

	t.Run("made-up dotted value", func(t *testing.T) {
		for _, hint := range []string{"", wicket.TokenTypeHintsAccessToken, wicket.TokenTypeHintsRefreshToken} {
			answer := revokeAs(t, pipeline, clientA, "aaa.bbb.ccc", hint)
			requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")
		}
	})
}

func TestRevocationJwtAccessTokenWithUnsupportedHint(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)
	require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")

	answer := revokeAs(t, pipeline, clientA, tokens.jwt, "id_token")
	requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")

	require.True(t, introspectActive(t, pipeline, tokens.jwt))
}

// A refused JWT access token and an unsupported hint share an error code, and
// a client must not be able to tell which of the two it ran into.
func TestRevocationJwtRejectionMatchesUnsupportedHintAnswer(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)
	require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")

	byForm := revokeAs(t, pipeline, clientA, tokens.jwt, wicket.TokenTypeHintsAccessToken)
	byHint := revokeAs(t, pipeline, clientA, "anything", "id_token")

	requireRevocationError(t, byHint, http.StatusBadRequest, "unsupported_token_type")
	require.Equal(t, byHint.status, byForm.status)
	require.Equal(t, byHint.body, byForm.body)
	// Date is the server's clock at each answer, not part of either answer.
	byForm.header.Del("Date")
	byHint.header.Del("Date")
	require.Equal(t, byHint.header, byForm.header)
}

func TestRevocationJwtAccessTokenWithHeaderCredentials(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)
	require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")

	answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {tokens.jwt}}, basicClient: clientA, basicSecret: secret})

	requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")
	require.Empty(t, answer.header.Get("WWW-Authenticate"))
}

// A request that fails client authentication is answered invalid_client
// whatever the form of its token, so the endpoint cannot be probed without
// credentials.
func TestRevocationClientAuthenticationPrecedesJwtRejection(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)
	require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")

	t.Run("wrong secret in Basic header is 401", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {tokens.jwt}}, basicClient: clientA, basicSecret: "wrong"})
		requireRevocationError(t, answer, http.StatusUnauthorized, "invalid_client")
		require.Equal(t, `Basic realm="wicket"`, answer.header.Get("WWW-Authenticate"))
	})

	t.Run("no credentials is 400", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {tokens.jwt}}})
		requireRevocationError(t, answer, http.StatusBadRequest, "invalid_client")
	})
}

func TestRevocationJwtRejectionHasNoSideEffects(t *testing.T) {
	pipeline := newRevocationPipeline()
	tokens := issueTokens(t, pipeline, clientA)
	require.Contains(t, tokens.jwt, ".", "token endpoint must issue a JWT access token")

	for _, hint := range []string{"", wicket.TokenTypeHintsAccessToken, wicket.TokenTypeHintsRefreshToken} {
		answer := revokeAs(t, pipeline, clientA, tokens.jwt, hint)
		requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")
	}

	require.True(t, introspectActive(t, pipeline, tokens.reference), "a refused request must not touch the reference token")
	requireRefreshUsable(t, pipeline, clientA, tokens.refresh)
}

// A reference token store accepts any handle a host writes, but a handle with
// a dot never passed access token validation, which reads a dotted value as a
// JWT. This pins the matching limitation of the revocation endpoint: such a
// handle is refused and stays in the store, so the host can only remove it
// from the store directly. Update this test together with that behavior.
func TestRevocationKnownLimitationDottedReferenceHandleCannotBeRevoked(t *testing.T) {
	pipeline := newRevocationPipeline()
	handle := "host.written.handle"
	require.Contains(t, handle, ".")
	pipeline.storeReferenceTokenUnder(t, clientA, handle)
	stored, err := pipeline.referenceTokens.GetReferenceToken(context.Background(), handle)
	require.NoError(t, err)
	require.NotNil(t, stored)

	for _, hint := range []string{wicket.TokenTypeHintsAccessToken, ""} {
		answer := revokeAs(t, pipeline, clientA, handle, hint)
		requireRevocationError(t, answer, http.StatusBadRequest, "unsupported_token_type")
	}

	stored, err = pipeline.referenceTokens.GetReferenceToken(context.Background(), handle)
	require.NoError(t, err, "the handle must still be in the store")
	require.NotNil(t, stored)
	require.Equal(t, clientA, stored.ClientId)
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

func discoveryDocument(t *testing.T, pipeline *integration_common.WicketPipeline) string {
	t.Helper()
	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.DiscoveryEndpoint)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "discovery: %s", body)
	return string(body)
}

func requireRevocationNotFound(t *testing.T, answer revocationAnswer) {
	t.Helper()
	require.Equal(t, http.StatusNotFound, answer.status, "revocation: %s", answer.body)
	require.Empty(t, answer.body)
	require.Empty(t, answer.header.Values("WWW-Authenticate"))
}

func TestRevocationSwitchedOff(t *testing.T) {
	pipeline := newRevocationPipeline()
	pipeline.Options.Endpoints.EnableTokenRevocationEndpoint = false

	t.Run("a valid request is not found and revokes nothing", func(t *testing.T) {
		tokens := issueTokens(t, pipeline, clientA)

		requireRevocationNotFound(t, revokeAs(t, pipeline, clientA, tokens.refresh, wicket.TokenTypeHintsRefreshToken))
		requireRevocationNotFound(t, revoke(t, pipeline, revocationCall{form: url.Values{"token": {tokens.refresh}}, basicClient: clientA, basicSecret: secret}))

		require.True(t, introspectActive(t, pipeline, tokens.reference))
		requireRefreshUsable(t, pipeline, clientA, tokens.refresh)
	})

	t.Run("GET is not found", func(t *testing.T) {
		response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.RevocationEndpoint)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		_ = response.Body.Close()
		require.Equal(t, http.StatusNotFound, response.StatusCode)
		require.Empty(t, body)
	})

	t.Run("JSON body is not found", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{contentType: "application/json", basicClient: clientA, basicSecret: secret})
		requireRevocationNotFound(t, answer)
	})

	t.Run("no credentials is not found", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {"anything"}}})
		requireRevocationNotFound(t, answer)
	})

	t.Run("wrong secret in Basic header is not found", func(t *testing.T) {
		answer := revoke(t, pipeline, revocationCall{form: url.Values{"token": {"anything"}}, basicClient: clientA, basicSecret: "wrong"})
		requireRevocationNotFound(t, answer)
	})

	t.Run("discovery does not advertise the endpoint", func(t *testing.T) {
		document := discoveryDocument(t, pipeline.WicketPipeline)
		require.False(t, gjson.Get(document, "revocation_endpoint").Exists(), "discovery: %s", document)
	})
}

// Known limitation, to be fixed in the discovery filter: the filter keeps a
// host's custom entry by where its value points and does not look at the
// endpoint switch. With the revocation endpoint switched off, a custom
// revocation_endpoint entry pointing back at this server's revocation route
// therefore stays in the document although the route answers 404. Update this
// test together with the filter.
func TestRevocationKnownLimitationSwitchedOffCustomEntryIsStillAdvertised(t *testing.T) {
	for name, entry := range map[string]func(pipeline *revocationFixture) string{
		"relative path": func(*revocationFixture) string { return "~/connect/revocation" },
		"absolute URL": func(pipeline *revocationFixture) string {
			return pipeline.TestServer.URL + "/connect/revocation"
		},
	} {
		t.Run(name, func(t *testing.T) {
			pipeline := newRevocationPipeline()
			pipeline.Options.Endpoints.EnableTokenRevocationEndpoint = false
			pipeline.Options.Discovery.CustomEntries["revocation_endpoint"] = entry(pipeline)

			document := discoveryDocument(t, pipeline.WicketPipeline)
			advertised := gjson.Get(document, "revocation_endpoint")
			require.True(t, advertised.Exists(), "discovery: %s", document)
			require.Equal(t, pipeline.TestServer.URL+"/connect/revocation", advertised.String())

			tokens := issueTokens(t, pipeline, clientA)
			form := url.Values{
				"client_id":       {clientA},
				"client_secret":   {secret},
				"token":           {tokens.refresh},
				"token_type_hint": {wicket.TokenTypeHintsRefreshToken},
			}
			response, err := pipeline.BackChannelClient.PostForm(advertised.String(), form)
			require.NoError(t, err)
			_ = response.Body.Close()
			require.Equal(t, http.StatusNotFound, response.StatusCode)
			requireRefreshUsable(t, pipeline, clientA, tokens.refresh)
		})
	}
}
