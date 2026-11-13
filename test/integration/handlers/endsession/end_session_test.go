// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package endsession

import (
	"context"
	htmlpkg "html"
	"io"
	"mime"
	"net/http"
	urlpkg "net/url"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func implicitClient(id string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesImplicit); err != nil {
		panic(err)
	}
	client.RequireConsent = false
	client.AllowedScopes = []string{"openid"}
	client.RedirectUris = []string{"https://" + id + "/callback"}
	client.AllowAccessTokensViaBrowser = true
	return client
}

func newEndSessionPipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	client1 := implicitClient("client1")
	client1.FrontChannelLogoutUri = "https://client1/signout"
	client1.PostLogoutRedirectUris = []string{"https://client1/signout-callback"}

	client2 := implicitClient("client2")
	client2.FrontChannelLogoutUri = "https://client2/signout"
	client2.PostLogoutRedirectUris = []string{
		"https://client2/signout-callback",
		"https://client2/signout-callback2",
	}

	client4 := implicitClient("client4")
	client4.FrontChannelLogoutUri = "https://client4/signout"

	pipeline.Clients = []*storage_models.Client{client1, client2, client4}

	user := test.NewTestUser()
	user.SubjectId = "bob"
	user.Username = "bob"
	user.Claims = []*claimspkg.Claim{
		claimspkg.NewClaim(claimspkg.WithClaimType("name"), claimspkg.WithClaimValue("Bob Loblaw")),
	}
	pipeline.Users = append(pipeline.Users, user)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())

	pipeline.Initialize()

	// Host wiring the cookie-options post-configuration would normally apply:
	// the logout page path defaults to the host logout route, and server-side
	// sessions are on so the sign-out iframe carries a session id.
	pipeline.Options.UserInteraction.LogoutUrl = wicket.UIConstantsDefaultRoutePathsLogout
	pipeline.Options.ServerSideSessions.Enabled = true
	// The httptest server speaks plain HTTP, so the session cookie must not be
	// marked Secure or the client jar will never send it back.
	pipeline.Options.ServerSideSessions.CookieSecure = false
	return pipeline
}

// resolveLocation absolutizes a redirect target against the test server, since
// a server-relative Location header names the same destination.
func resolveLocation(t *testing.T, pipeline *integration_common.WicketPipeline, location string) string {
	t.Helper()
	if strings.HasPrefix(location, "/") {
		return pipeline.TestServer.URL + location
	}
	return location
}

func issueIdentityToken(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string) string {
	t.Helper()

	authorization := pipeline.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "id_token",
		Scope:        "openid",
		RedirectUri:  "https://" + clientId + "/callback",
		State:        "123_state",
		Nonce:        "123_nonce",
	})
	require.NotNil(t, authorization)
	idToken := authorization.IdentityToken()
	require.NotEmpty(t, idToken)
	return idToken
}

func endSessionUrl(t *testing.T, pipeline *integration_common.WicketPipeline, query string) string {
	t.Helper()

	base, err := urlpkg.JoinPath(pipeline.TestServer.URL, integration_common.EndSessionEndpoint)
	require.NoError(t, err)
	if query != "" {
		base += "?" + query
	}
	return base
}

func TestEndSessionEndpointResponds(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	response, err := pipeline.BackChannelClient.Get(endSessionUrl(t, pipeline, ""))

	a.NoError(err)
	a.NotEqual(http.StatusNotFound, response.StatusCode)
}

func TestAnonymousSignoutReachesTheLogoutPage(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	_, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline, ""))

	a.NoError(err)
	a.True(pipeline.LogoutWasCalled)
}

func TestSignoutRedirectsToTheConfiguredLogoutPath(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()
	pipeline.Options.UserInteraction.LogoutUrl = "/logout"
	pipeline.Options.UserInteraction.LogoutIdParameter = "id"

	a.NoError(pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "client1")

	pipeline.BrowserClient.AllowAutoRedirect = false
	response, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline,
		"id_token_hint="+idToken+"&post_logout_redirect_uri=https://client1/signout-callback"))
	a.NoError(err)

	a.Equal(http.StatusFound, response.StatusCode)
	a.True(strings.HasPrefix(resolveLocation(t, pipeline, response.Header.Get("Location")), pipeline.TestServer.URL+"/logout?id="))
}

func TestLogoutContextCarriesTheRequestParameters(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	a.NoError(pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "client2")

	_, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline,
		"id_token_hint="+idToken+"&post_logout_redirect_uri=https://client2/signout-callback2&ui_locales=fr-FR%20fr-CA"))
	a.NoError(err)

	a.True(pipeline.LogoutWasCalled)
	a.NotNil(pipeline.LogoutRequest)
	a.Equal("client2", pipeline.LogoutRequest.ClientId)
	a.Equal("https://client2/signout-callback2", pipeline.LogoutRequest.PostLogoutRedirectUri)
	a.Equal("fr-FR fr-CA", pipeline.LogoutRequest.UiLocales)
}

func TestOverlongUiLocalesAreIgnored(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	a.NoError(pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "client2")

	_, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline,
		"id_token_hint="+idToken+"&post_logout_redirect_uri=https://client2/signout-callback2&ui_locales="+strings.Repeat("X", 101)))
	a.NoError(err)

	a.True(pipeline.LogoutWasCalled)
	a.NotNil(pipeline.LogoutRequest)
	a.Equal("client2", pipeline.LogoutRequest.ClientId)
	a.Equal("https://client2/signout-callback2", pipeline.LogoutRequest.PostLogoutRedirectUri)
	a.Empty(pipeline.LogoutRequest.UiLocales)
}

func TestSignedOutUserStillPassesRedirectInformation(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	a.NoError(pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "client2")

	pipeline.RemoveLoginCookie()

	_, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline,
		"id_token_hint="+idToken+"&post_logout_redirect_uri=https://client2/signout-callback2"))
	a.NoError(err)

	a.True(pipeline.LogoutWasCalled)
	a.NotNil(pipeline.LogoutRequest)
	a.Equal("client2", pipeline.LogoutRequest.ClientId)
	a.Equal("https://client2/signout-callback2", pipeline.LogoutRequest.PostLogoutRedirectUri)
	a.Empty(pipeline.LogoutRequest.SignOutIFrameUrl)
}

func TestSignoutSupportsPost(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	a.NoError(pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "client1")

	values := urlpkg.Values{}
	values.Add("id_token_hint", idToken)
	values.Add("post_logout_redirect_uri", "https://client1/signout-callback")

	request, err := http.NewRequest(http.MethodPost, pipeline.TestServer.URL+integration_common.EndSessionEndpoint, strings.NewReader(values.Encode()))
	a.NoError(err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err = pipeline.BrowserClient.Do(request)
	a.NoError(err)

	a.True(pipeline.LogoutWasCalled)
	a.NotNil(pipeline.LogoutRequest)
	a.Equal("client1", pipeline.LogoutRequest.ClientId)
	a.Equal("https://client1/signout-callback", pipeline.LogoutRequest.PostLogoutRedirectUri)
}

func TestIdTokenHintAloneSelectsNoPostLogoutRedirectUri(t *testing.T) {
	for name, clientId := range map[string]string{
		"single registered uri is not auto-selected":       "client1",
		"multiple registered uris are never auto-selected": "client2",
	} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			pipeline := newEndSessionPipeline()

			a.NoError(pipeline.Login("bob"))
			idToken := issueIdentityToken(t, pipeline, clientId)

			_, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline, "id_token_hint="+idToken))
			a.NoError(err)

			a.NotNil(pipeline.LogoutRequest)
			a.Empty(pipeline.LogoutRequest.PostLogoutRedirectUri)
		})
	}
}

func TestMismatchedPostLogoutRedirectUriIsDropped(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	a.NoError(pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "client1")

	_, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline,
		"id_token_hint="+idToken+"&post_logout_redirect_uri=https://client1/signout-callback-not-valid"))
	a.NoError(err)

	a.NotNil(pipeline.LogoutRequest)
	a.NotEmpty(pipeline.LogoutRequest.ClientId)
	a.Empty(pipeline.LogoutRequest.PostLogoutRedirectUri)
}

func TestMismatchedIdTokenHintDropsTheClientInformation(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()
	pipeline.Users = append(pipeline.Users, func() *test.TestUser {
		user := test.NewTestUser()
		user.SubjectId = "alice"
		user.Username = "alice"
		return user
	}())

	a.NoError(pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "client1")

	a.NoError(pipeline.Login("alice"))

	_, err := pipeline.BrowserClient.Get(endSessionUrl(t, pipeline,
		"id_token_hint="+idToken+"&post_logout_redirect_uri=https://client1/signout-callback"))
	a.NoError(err)

	a.NotNil(pipeline.LogoutRequest)
	a.Empty(pipeline.LogoutRequest.ClientId)
	a.Empty(pipeline.LogoutRequest.PostLogoutRedirectUri)
}

func TestSignoutCallbackWithoutParametersIsBadRequest(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	callbackUrl, err := urlpkg.JoinPath(pipeline.TestServer.URL, integration_common.EndSessionCallbackEndpoint)
	a.NoError(err)

	response, err := pipeline.BackChannelClient.Get(callbackUrl)

	a.NoError(err)
	a.Equal(http.StatusBadRequest, response.StatusCode)
}

// signoutFrameUrl publishes a front-channel notification context directly and
// returns the callback iframe address carrying its handle, standing in for the
// session state a full sign-out would have accumulated.
func signoutFrameUrl(t *testing.T, pipeline *integration_common.WicketPipeline, sessionId string, clientIds ...string) string {
	t.Helper()

	store := pipeline.Root.NewMessageStore_contexts_LogoutNotificationContext()
	clock := godi.GetRequired[services.SystemClock](pipeline.Root)
	handle, err := store.Write(context.Background(), messages.NewMessageWithCreated(&contexts.LogoutNotificationContext{
		SubjectId: "bob",
		SessionId: sessionId,
		ClientIds: clientIds,
	}, clock.Now().Unix()))
	require.NoError(t, err)

	return pipeline.TestServer.URL + integration_common.EndSessionCallbackEndpoint + "?endSessionId=" + urlpkg.QueryEscape(handle)
}

func TestValidSignoutCallbackReturnsHtml(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	response, err := pipeline.BrowserClient.Get(signoutFrameUrl(t, pipeline, "session-1", "client1"))
	a.NoError(err)
	a.Equal(http.StatusOK, response.StatusCode)

	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	a.Equal("text/html", mediaType)
}

func TestValidSignoutCallbackRendersIframesWithSessionParameters(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	sid := "session-1"
	response, err := pipeline.BrowserClient.Get(signoutFrameUrl(t, pipeline, sid, "client1", "client2"))
	a.NoError(err)

	html, err := io.ReadAll(response.Body)
	a.NoError(err)

	query := "iss=" + urlpkg.QueryEscape(pipeline.TestServer.URL) + "&sid=" + urlpkg.QueryEscape(sid)
	a.Contains(string(html), htmlpkg.EscapeString("https://client1/signout?"+query))
}

func TestSignoutCallbackUsesCleanupParameterForNonOidcClient(t *testing.T) {
	a := require.New(t)

	pipeline := newEndSessionPipeline()

	frameUrl := signoutFrameUrl(t, pipeline, "session-1", "client4")

	// The non-OIDC protocol type exercises the cleanup-parameter branch.
	for _, client := range pipeline.Clients {
		if client.ClientId == "client4" {
			client.ProtocolType = wicket.ProtocolTypesSaml2p
		}
	}

	response, err := pipeline.BrowserClient.Get(frameUrl)
	a.NoError(err)

	html, err := io.ReadAll(response.Body)
	a.NoError(err)

	a.Contains(string(html), htmlpkg.EscapeString("https://client4/signout?wa=wsignoutcleanup1.0"))
}
