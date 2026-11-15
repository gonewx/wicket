// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package orphanedgrants covers the revocation of the grants a browser
// session holds once another user signs in on that browser.
package orphanedgrants

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	clientId     = "orphaned.client"
	clientSecret = "secret"
	redirectUri  = "https://client.example/callback"

	alice = "alice"
	bob   = "bob"
)

// failingCodeStore is the in-memory authorization code store whose removal
// by session fails, and which records that it was asked. The authorization
// codes are the first grants revoked.
type failingCodeStore struct {
	*storage_impl.AuthorizationCodeStore
	asked int
}

func (s *failingCodeStore) RemoveAuthorizationCodesBySession(context.Context, string) (int, error) {
	s.asked++
	return 0, errors.New("authorization code store unavailable")
}

type setup struct {
	revoke      bool
	consumption *services.RefreshTokenConsumption
	codes       *failingCodeStore
	// reference issues reference access tokens.
	reference bool
}

type fixture struct {
	*integration_common.WicketPipeline
	// browsers are two browsers with their own cookie jars.
	browsers [2]*integration_common.BrowserClient
}

func newFixture(t *testing.T, s setup) *fixture {
	t.Helper()
	pipeline := integration_common.NewWicketPipeline()
	cfg := pipeline.Root.ServerConfig()
	if s.revoke {
		cfg.SetRevokeGrantsOnSessionSubjectChange(true)
	}
	if s.consumption != nil {
		cfg.SetRefreshTokenConsumption(*s.consumption)
	}
	if s.codes != nil {
		cfg.SetAuthorizationCodeStore(s.codes)
	}

	client := storage_models.NewClient()
	client.ClientId = clientId
	secret := storage_models.NewSecret()
	secret.Value = utils.Sha256(clientSecret)
	client.ClientSecrets = []*storage_models.Secret{secret}
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesCode); err != nil {
		t.Fatal(err)
	}
	client.AllowedScopes = []string{wicket.StandardScopesOpenId, "api1"}
	client.AllowOfflineAccess = true
	client.RequirePkce = false
	client.RequireConsent = false
	client.RedirectUris = []string{redirectUri}
	if s.reference {
		client.AccessTokenType = wicket.AccessTokenTypeReference
	}
	if s.consumption != nil {
		client.RefreshTokenUsage = wicket.TokenUsageOneTimeOnly
	} else {
		client.RefreshTokenUsage = wicket.TokenUsageReUse
	}
	pipeline.Clients = append(pipeline.Clients, client)
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	resource := storage_models.NewApiResource()
	resource.Name = "api1"
	resource.Scopes = []string{"api1"}
	apiSecret := storage_models.NewSecret()
	apiSecret.Value = utils.Sha256(clientSecret)
	resource.ApiSecrets = []*storage_models.Secret{apiSecret}
	pipeline.ApiResources = append(pipeline.ApiResources, resource)
	scope := storage_models.NewApiScope()
	scope.Name = "api1"
	pipeline.ApiScopes = append(pipeline.ApiScopes, scope)

	pipeline.Initialize()
	// The browser session lives in a server-side session; the test server
	// speaks plain HTTP, so the session cookie must not be marked Secure.
	pipeline.Options.ServerSideSessions.Enabled = true
	pipeline.Options.ServerSideSessions.CookieSecure = false
	t.Cleanup(pipeline.TestServer.Close)

	// The second browser gets its own client: a browser client keeps its
	// cookie jar and redirect policy on the client it is given.
	second := *pipeline.TestServer.Client()
	return &fixture{
		WicketPipeline: pipeline,
		browsers:       [2]*integration_common.BrowserClient{pipeline.BrowserClient, integration_common.NewBrowserClient(&second)},
	}
}

// use makes browser the one the pipeline drives.
func (f *fixture) use(browser int) {
	f.BrowserClient = f.browsers[browser]
}

func (f *fixture) sessionCookie(t *testing.T, browser int) string {
	t.Helper()
	cookie := f.browsers[browser].GetCookie(f.TestServer.URL, "wicket.session")
	require.NotNil(t, cookie, "browser %d holds a session cookie", browser)
	return cookie.Value
}

func (f *fixture) login(t *testing.T, browser int, subject string) {
	t.Helper()
	f.use(browser)
	require.NoError(t, f.Login(subject))
}

// code runs the authorize endpoint in browser and returns the code.
func (f *fixture) code(t *testing.T, browser int) string {
	t.Helper()
	f.use(browser)
	authorization := f.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "code",
		Scope:        "openid api1 offline_access",
		RedirectUri:  redirectUri,
		State:        "state",
		Nonce:        "nonce",
	})
	require.NotNil(t, authorization)
	require.NotEmpty(t, authorization.Code())
	return authorization.Code()
}

func (f *fixture) token(t *testing.T, form url.Values) (int, string) {
	t.Helper()
	form.Set("client_id", clientId)
	form.Set("client_secret", clientSecret)
	response, err := f.BackChannelClient.PostForm(f.TestServer.URL+integration_common.TokenEndpoint, form)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

// accessToken redeems a fresh code of browser and returns the access token.
func (f *fixture) accessToken(t *testing.T, browser int) string {
	t.Helper()
	status, body := f.token(t, redeemCode(f.code(t, browser)))
	require.Equal(t, http.StatusOK, status, "code exchange: %s", body)
	access := gjson.Get(body, "access_token").String()
	require.NotEmpty(t, access, "code exchange: %s", body)
	return access
}

// active introspects token as the API and reports whether it is active.
func (f *fixture) active(t *testing.T, token string) bool {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, f.TestServer.URL+integration_common.IntrospectionEndpoint,
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	require.NoError(t, err)
	request.SetBasicAuth("api1", clientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := f.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode, "introspection: %s", body)
	return gjson.GetBytes(body, "active").Bool()
}

func redeemCode(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectUri}}
}

func redeemRefresh(refresh string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}
}

// refreshToken redeems a fresh code of browser and returns the refresh token.
func (f *fixture) refreshToken(t *testing.T, browser int) string {
	t.Helper()
	status, body := f.token(t, redeemCode(f.code(t, browser)))
	require.Equal(t, http.StatusOK, status, "code exchange: %s", body)
	refresh := gjson.Get(body, "refresh_token").String()
	require.NotEmpty(t, refresh, "code exchange: %s", body)
	return refresh
}

// redeem exchanges refresh and returns the refresh token of the response.
func (f *fixture) redeem(t *testing.T, refresh string) string {
	t.Helper()
	status, body := f.token(t, redeemRefresh(refresh))
	require.Equal(t, http.StatusOK, status, "refresh exchange: %s", body)
	next := gjson.Get(body, "refresh_token").String()
	require.NotEmpty(t, next, "refresh exchange: %s", body)
	return next
}

func (f *fixture) requireInvalidGrant(t *testing.T, form url.Values) {
	t.Helper()
	status, body := f.token(t, form)
	require.Equal(t, http.StatusBadRequest, status, "token endpoint: %s", body)
	require.Equal(t, "invalid_grant", gjson.Get(body, "error").String(), "token endpoint: %s", body)
}

// sharedBrowser runs the common scene: alice obtains a refresh token in each
// browser and an unredeemed code in browser 0, then bob signs in on browser
// 0. It returns alice's refresh tokens and her unredeemed code.
func sharedBrowser(t *testing.T, f *fixture) (first, second, pending string) {
	t.Helper()
	f.login(t, 0, alice)
	first = f.refreshToken(t, 0)
	pending = f.code(t, 0)

	f.login(t, 1, alice)
	second = f.refreshToken(t, 1)
	require.NotEqual(t, f.sessionCookie(t, 0), f.sessionCookie(t, 1), "each browser has its own session")

	former := f.sessionCookie(t, 0)
	f.login(t, 0, bob)
	require.NotEqual(t, former, f.sessionCookie(t, 0), "bob signs in on a new session")
	return first, second, pending
}

func requireBobSignedIn(t *testing.T, f *fixture) {
	t.Helper()
	status, body := f.token(t, redeemCode(f.code(t, 0)))
	require.Equal(t, http.StatusOK, status, "bob's code exchange: %s", body)
	require.NotEmpty(t, gjson.Get(body, "refresh_token").String())
}

func TestAnotherUserSigningInRevokesTheFormerSessionsGrants(t *testing.T) {
	f := newFixture(t, setup{revoke: true})
	first, second, pending := sharedBrowser(t, f)

	f.requireInvalidGrant(t, redeemRefresh(first))
	f.redeem(t, second)
	f.requireInvalidGrant(t, redeemCode(pending))
	requireBobSignedIn(t, f)
}

func TestGrantsAreKeptWithoutTheDeclaration(t *testing.T) {
	f := newFixture(t, setup{})
	first, second, pending := sharedBrowser(t, f)

	f.redeem(t, first)
	f.redeem(t, second)
	status, body := f.token(t, redeemCode(pending))
	require.Equal(t, http.StatusOK, status, "the pending code is still redeemable: %s", body)
	requireBobSignedIn(t, f)
}

func TestTheSameUserSigningInAgainKeepsTheGrants(t *testing.T) {
	f := newFixture(t, setup{revoke: true})
	f.login(t, 0, alice)
	refresh := f.refreshToken(t, 0)

	f.login(t, 0, alice)

	f.redeem(t, refresh)
}

func TestARotatedRefreshTokenIsRevokedWithItsSession(t *testing.T) {
	for name, consumption := range map[string]services.RefreshTokenConsumption{
		"removed on redemption": services.RefreshTokenRemovedOnRedemption,
		"marked on redemption":  services.RefreshTokenMarkedOnRedemption,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, setup{revoke: true, consumption: &consumption})
			f.login(t, 0, alice)
			refresh := f.refreshToken(t, 0)
			rotated := f.redeem(t, refresh)
			require.NotEqual(t, refresh, rotated)

			f.login(t, 0, bob)

			f.requireInvalidGrant(t, redeemRefresh(rotated))
			requireBobSignedIn(t, f)
		})
	}
}

func TestAFailingStoreDoesNotStopTheRevocationOrTheSignIn(t *testing.T) {
	codes := &failingCodeStore{AuthorizationCodeStore: storage_impl.NewAuthorizationCodeStore()}
	f := newFixture(t, setup{revoke: true, codes: codes})
	first, second, pending := sharedBrowser(t, f)

	require.Equal(t, 1, codes.asked)
	// The refresh tokens are revoked after the failed removal of the codes.
	f.requireInvalidGrant(t, redeemRefresh(first))
	f.redeem(t, second)
	// The failing store removed nothing, so alice's pending code survives.
	status, body := f.token(t, redeemCode(pending))
	require.Equal(t, http.StatusOK, status, "the pending code was not removed: %s", body)
	requireBobSignedIn(t, f)
}

func TestReferenceTokensOfTheFormerSessionAreRevoked(t *testing.T) {
	f := newFixture(t, setup{revoke: true, reference: true})
	f.login(t, 0, alice)
	first := f.accessToken(t, 0)
	f.login(t, 1, alice)
	second := f.accessToken(t, 1)
	require.True(t, f.active(t, first))
	require.True(t, f.active(t, second))

	f.login(t, 0, bob)

	require.False(t, f.active(t, first), "alice's reference token of the shared browser")
	require.True(t, f.active(t, second), "alice's reference token of her other browser")
}

func TestPersistedGrantsOfTheFormerSessionAreRevoked(t *testing.T) {
	f := newFixture(t, setup{revoke: true})
	f.login(t, 0, alice)
	f.login(t, 1, alice)
	grants := godi.GetRequired[storage.PersistedGrantStore](f.Root)
	ctx := context.Background()
	now := godi.GetRequired[services.SystemClock](f.Root).Now()
	for key, session := range map[string]string{"shared": f.sessionCookie(t, 0), "other": f.sessionCookie(t, 1)} {
		require.NoError(t, grants.Store(ctx, &storage_models.PersistedGrant{
			Key: key, Type: "test", SubjectId: alice, ClientId: clientId, SessionId: session, CreationTime: now,
		}))
	}

	f.login(t, 0, bob)

	_, err := grants.Get(ctx, "shared")
	require.ErrorIs(t, err, storage.ErrNotFound, "the grant of the shared browser's session is removed")
	_, err = grants.Get(ctx, "other")
	require.NoError(t, err, "the grant of alice's other session is kept")
}
