// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package backchannellogout

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	urlpkg "net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	sessionpkg "github.com/gonewx/wicket/session"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

const backChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// relyingParty is a back-channel logout receiver: it records every logout
// token posted to it and answers with the configured status. When block is
// set, it holds each request until the channel is closed.
type relyingParty struct {
	server *httptest.Server
	status int
	block  chan struct{}

	mu          sync.Mutex
	tokens      []string
	contentType []string
}

func newRelyingParty(t *testing.T, status int) *relyingParty {
	t.Helper()
	rp := &relyingParty{status: status}
	rp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rp.block != nil {
			<-rp.block
		}
		if err := r.ParseForm(); err == nil {
			rp.mu.Lock()
			rp.tokens = append(rp.tokens, r.PostForm.Get("logout_token"))
			rp.contentType = append(rp.contentType, r.Header.Get("Content-Type"))
			rp.mu.Unlock()
		}
		w.WriteHeader(rp.status)
	}))
	t.Cleanup(rp.server.Close)
	return rp
}

// blocking makes the receiver hold requests; the hold is released before the
// server closes, since cleanups run in reverse registration order.
func (rp *relyingParty) blocking(t *testing.T) {
	t.Helper()
	rp.block = make(chan struct{})
	t.Cleanup(func() { close(rp.block) })
}

func (rp *relyingParty) received() []string {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return append([]string(nil), rp.tokens...)
}

func (rp *relyingParty) uri() string {
	return rp.server.URL + "/backchannel-logout"
}

func relyingPartyClient(id string, rp *relyingParty) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesImplicit); err != nil {
		panic(err)
	}
	client.RequireConsent = false
	client.AllowedScopes = []string{"openid"}
	client.RedirectUris = []string{"https://" + id + "/callback"}
	client.AllowAccessTokensViaBrowser = true
	if rp != nil {
		client.BackChannelLogoutUri = rp.uri()
	}
	return client
}

// newPipeline assembles the default composition root with the given clients
// and the host wiring an end-session flow needs. The host injects an HTTP
// client that reaches the local receivers. Server-side sessions stay off, as
// in the default assembly.
func newPipeline(clients ...*storage_models.Client) *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()
	pipeline.Clients = clients
	pipeline.IdentityScopes = append(pipeline.IdentityScopes, storage_models.IdentityResourcesOpenId())
	pipeline.Initialize()

	pipeline.Options.UserInteraction.LogoutUrl = wicket.UIConstantsDefaultRoutePathsLogout
	pipeline.Root.ServerConfig().SetBackChannelLogoutHttpClient(&http.Client{Timeout: 5 * time.Second})
	return pipeline
}

// newSessionPipeline is newPipeline with server-side sessions enabled, the
// assembly in which back-channel logout is delivered. The test server speaks
// plain HTTP, so the session cookie must not be marked Secure.
func newSessionPipeline(clients ...*storage_models.Client) *integration_common.WicketPipeline {
	pipeline := newPipeline(clients...)
	pipeline.Options.ServerSideSessions.Enabled = true
	pipeline.Options.ServerSideSessions.CookieSecure = false
	return pipeline
}

func sessionCookieName(pipeline *integration_common.WicketPipeline) string {
	if name := pipeline.Options.ServerSideSessions.CookieName; name != "" {
		return name
	}
	return "wicket.session"
}

func issueIdentityToken(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string) string {
	t.Helper()
	authorization := pipeline.RequestAuthorizationEndpoint(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "id_token",
		Scope:        "openid",
		RedirectUri:  "https://" + clientId + "/callback",
		State:        "state",
		Nonce:        "nonce",
	})
	require.NotNil(t, authorization)
	idToken := authorization.IdentityToken()
	require.NotEmpty(t, idToken)
	return idToken
}

// signOut sends the end-session request (with the identity token as hint when
// given), lets the host logout page read the logout context and sign the user
// out, and returns the callback iframe address that page would render, which
// is empty when the provider offers none.
func signOut(t *testing.T, pipeline *integration_common.WicketPipeline, idToken string) string {
	t.Helper()
	endSession, err := urlpkg.JoinPath(pipeline.TestServer.URL, integration_common.EndSessionEndpoint)
	require.NoError(t, err)
	if idToken != "" {
		endSession += "?id_token_hint=" + urlpkg.QueryEscape(idToken)
	}
	pipeline.LogoutWasCalled = false
	pipeline.LogoutRequest = nil
	response, err := pipeline.BrowserClient.Get(endSession)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.True(t, pipeline.LogoutWasCalled)
	require.NotNil(t, pipeline.LogoutRequest)
	return pipeline.LogoutRequest.SignOutIFrameUrl
}

// seedSession records a server-side session in the container's session store,
// standing in for the session a sign-in to those clients would have created.
func seedSession(t *testing.T, pipeline *integration_common.WicketPipeline, sessionId string, subjectId string, clientIds ...string) {
	t.Helper()
	at := now(pipeline)
	require.NoError(t, godi.GetRequired[sessionpkg.Store](pipeline.Root).CreateSession(context.Background(), &sessionpkg.Record{
		SessionID: sessionId,
		SubjectID: subjectId,
		Created:   at,
		Renewed:   at,
		Expires:   at.Add(time.Hour),
		ClientIDs: clientIds,
	}))
}

// publishLogoutContext publishes a logout context naming no subject through
// the container's logout context store, as the host logout page does when it
// reads the logout context, and returns the callback iframe address carrying
// its handle.
func publishLogoutContext(t *testing.T, pipeline *integration_common.WicketPipeline, created time.Time, sessionId string, clientIds ...string) string {
	t.Helper()
	store := pipeline.Root.NewMessageStore_contexts_LogoutNotificationContext()
	handle, err := store.Write(context.Background(), messages.NewMessageWithCreated(&contexts.LogoutNotificationContext{
		SessionId: sessionId,
		ClientIds: clientIds,
	}, created.Unix()))
	require.NoError(t, err)
	return pipeline.TestServer.URL + integration_common.EndSessionCallbackEndpoint + "?endSessionId=" + urlpkg.QueryEscape(handle)
}

func now(pipeline *integration_common.WicketPipeline) time.Time {
	return godi.GetRequired[services.SystemClock](pipeline.Root).Now()
}

// loadCallback loads the callback iframe and asserts it renders the HTML page.
func loadCallback(t *testing.T, pipeline *integration_common.WicketPipeline, frameUrl string) {
	t.Helper()
	response, err := pipeline.BrowserClient.Get(frameUrl)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	mediaType, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	require.Equal(t, "text/html", mediaType)
}

func getJson(t *testing.T, client *http.Client, address string) map[string]any {
	t.Helper()
	response, err := client.Get(address)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	document := map[string]any{}
	require.NoError(t, json.Unmarshal(body, &document))
	return document
}

func discovery(t *testing.T, pipeline *integration_common.WicketPipeline) map[string]any {
	t.Helper()
	return getJson(t, pipeline.TestServer.Client(), pipeline.TestServer.URL+integration_common.DiscoveryEndpoint)
}

// verifiedClaims checks the token signature against the JWKS published through
// discovery and returns its typ header and claims.
func verifiedClaims(t *testing.T, pipeline *integration_common.WicketPipeline, token string) (string, map[string]any) {
	t.Helper()
	jwksUri, ok := discovery(t, pipeline)["jwks_uri"].(string)
	require.True(t, ok)
	response, err := pipeline.TestServer.Client().Get(jwksUri)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	set, err := jwk.Parse(body)
	require.NoError(t, err)

	_, err = jwt.Parse([]byte(token), jwt.WithKeySet(set), jwt.WithValidate(false))
	require.NoError(t, err, "logout token must verify against the published JWKS")

	return unverifiedClaims(t, token)
}

func unverifiedClaims(t *testing.T, token string) (string, map[string]any) {
	t.Helper()
	msg, err := jws.Parse([]byte(token))
	require.NoError(t, err)
	typ, _ := msg.Signatures()[0].ProtectedHeaders().Type()
	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(msg.Payload(), &claims))
	return typ, claims
}

func TestDiscoveryAdvertisesBackChannelLogoutOnlyWithSessions(t *testing.T) {
	for name, tc := range map[string]struct {
		pipeline func() *integration_common.WicketPipeline
		want     bool
	}{
		"default assembly": {pipeline: func() *integration_common.WicketPipeline { return newPipeline() }},
		"server-side sessions": {
			pipeline: func() *integration_common.WicketPipeline { return newSessionPipeline() },
			want:     true,
		},
		"server-side sessions without check-session": {
			pipeline: func() *integration_common.WicketPipeline {
				pipeline := newSessionPipeline()
				pipeline.Options.Endpoints.EnableCheckSessionEndpoint = false
				return pipeline
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			document := discovery(t, tc.pipeline())

			if tc.want {
				require.Equal(t, true, document[wicket.DiscoveryBackchannelLogoutSupported])
				require.Equal(t, true, document["backchannel_logout_session_supported"])
				return
			}
			require.NotContains(t, document, wicket.DiscoveryBackchannelLogoutSupported)
			require.NotContains(t, document, "backchannel_logout_session_supported")
		})
	}
}

func TestFullSignOutDeliversAVerifiableLogoutToken(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("rp1", rp))

	require.NoError(t, pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "rp1")
	_, idClaims := unverifiedClaims(t, idToken)
	sid, ok := idClaims["sid"].(string)
	require.True(t, ok, "identity token issued within a session carries sid")
	require.NotEmpty(t, sid)

	require.NotNil(t, pipeline.BrowserClient.GetCookie(pipeline.TestServer.URL, sessionCookieName(pipeline)),
		"the browser holds the session cookie while signed in")
	frameUrl := signOut(t, pipeline, idToken)
	require.NotEmpty(t, frameUrl)
	require.Nil(t, pipeline.BrowserClient.GetCookie(pipeline.TestServer.URL, sessionCookieName(pipeline)),
		"signing out of the default scheme ends the session cookie")
	loadCallback(t, pipeline, frameUrl)

	tokens := rp.received()
	require.Len(t, tokens, 1)
	require.Equal(t, "application/x-www-form-urlencoded", rp.contentType[0])
	typ, claims := verifiedClaims(t, pipeline, tokens[0])

	require.Equal(t, "logout+jwt", typ)
	require.Equal(t, discovery(t, pipeline)["issuer"], claims["iss"])
	require.Contains(t, []any{"rp1", []any{"rp1"}}, claims["aud"])
	iat, ok := claims["iat"].(float64)
	require.True(t, ok)
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	require.Greater(t, exp, iat)
	require.LessOrEqual(t, exp-iat, float64(120))
	jti, ok := claims["jti"].(string)
	require.True(t, ok)
	require.NotEmpty(t, jti)
	events, ok := claims["events"].(map[string]any)
	require.True(t, ok, "events must be a JSON object")
	event, ok := events[backChannelLogoutEvent].(map[string]any)
	require.True(t, ok, "the logout event must be a JSON object")
	require.Empty(t, event)
	require.NotContains(t, claims, "nonce")
	require.Equal(t, sid, claims["sid"])
	require.Equal(t, "bob", claims["sub"])
}

func TestFullSignOutInTheDefaultAssemblyDeliversNothing(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newPipeline(relyingPartyClient("rp1", rp))

	require.NoError(t, pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "rp1")
	_, idClaims := unverifiedClaims(t, idToken)
	require.NotContains(t, idClaims, "sid")

	require.Empty(t, signOut(t, pipeline, idToken))
	require.Empty(t, rp.received())
	require.NotContains(t, discovery(t, pipeline), wicket.DiscoveryBackchannelLogoutSupported)
}

func TestFullSignOutWithoutCheckSessionDeliversNothing(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("rp1", rp))
	pipeline.Options.Endpoints.EnableCheckSessionEndpoint = false

	require.NoError(t, pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "rp1")

	if frameUrl := signOut(t, pipeline, idToken); frameUrl != "" {
		loadCallback(t, pipeline, frameUrl)
	}
	require.Empty(t, rp.received())
}

func TestAnonymousSignOutAfterLogoutDeliversNoMore(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("rp1", rp))

	require.NoError(t, pipeline.Login("bob"))
	idToken := issueIdentityToken(t, pipeline, "rp1")
	frameUrl := signOut(t, pipeline, idToken)
	require.NotEmpty(t, frameUrl)
	loadCallback(t, pipeline, frameUrl)
	require.Len(t, rp.received(), 1)

	require.Empty(t, signOut(t, pipeline, ""))
	require.Len(t, rp.received(), 1)
}

func TestAnotherUsersSessionIsNotAdopted(t *testing.T) {
	pipeline := newSessionPipeline(relyingPartyClient("rp1", nil))
	cookieName := sessionCookieName(pipeline)

	require.NoError(t, pipeline.Login("bob"))
	bobsSession := pipeline.BrowserClient.GetCookie(pipeline.TestServer.URL, cookieName)
	require.NotNil(t, bobsSession)

	require.NoError(t, pipeline.Login("alice"))
	server, err := urlpkg.Parse(pipeline.TestServer.URL)
	require.NoError(t, err)
	pipeline.BrowserClient.Jar.SetCookies(server, []*http.Cookie{{Name: cookieName, Value: bobsSession.Value, Path: "/"}})

	_, claims := unverifiedClaims(t, issueIdentityToken(t, pipeline, "rp1"))
	require.Equal(t, "alice", claims["sub"])
	require.NotContains(t, claims, "sid")
}

func TestSigningOutOfAnotherSchemeKeepsTheSession(t *testing.T) {
	pipeline := newSessionPipeline(relyingPartyClient("rp1", nil))
	cookieName := sessionCookieName(pipeline)

	// A host page signing out of a temporary external scheme, served from the
	// same container.
	host := httptest.NewServer(hosting.ScopeMiddleware(pipeline.Root)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := hosting.ScopeFrom(r.Context())
		contextAccessor := godi.GetRequired[accessor.HttpContextAccessor](scope)
		contextAccessor.SetRequest(r)
		if responseAccessor, ok := contextAccessor.(accessor.HttpResponseWriterAccessor); ok {
			responseAccessor.SetResponseWriter(w)
		}
		_ = godi.GetRequired[auth.Service](scope).SignOut(r, w, "external", nil)
		w.WriteHeader(http.StatusOK)
	})))
	t.Cleanup(host.Close)

	require.NoError(t, pipeline.Login("bob"))
	require.NotNil(t, pipeline.BrowserClient.GetCookie(pipeline.TestServer.URL, cookieName))

	response, err := pipeline.BrowserClient.Get(host.URL + "/signout-external")
	require.NoError(t, err)
	_ = response.Body.Close()

	require.NotNil(t, pipeline.BrowserClient.GetCookie(pipeline.TestServer.URL, cookieName))
	_, claims := unverifiedClaims(t, issueIdentityToken(t, pipeline, "rp1"))
	sid, ok := claims["sid"].(string)
	require.True(t, ok)
	require.NotEmpty(t, sid)
}

func TestForgedLogoutContextDeliversNothing(t *testing.T) {
	for name, newAssembly := range map[string]func(...*storage_models.Client) *integration_common.WicketPipeline{
		"default assembly":     newPipeline,
		"server-side sessions": newSessionPipeline,
	} {
		t.Run(name, func(t *testing.T) {
			rp := newRelyingParty(t, http.StatusOK)
			pipeline := newAssembly(relyingPartyClient("rp1", rp))

			loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline), "forged-session", "rp1"))

			require.Empty(t, rp.received())
		})
	}
}

func TestLogoutContextWithoutSessionDeliversNothing(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("rp1", rp))

	loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline), "", "rp1"))

	require.Empty(t, rp.received())
}

func TestOnlyClientsRecordedForTheSessionAreNotified(t *testing.T) {
	recorded := newRelyingParty(t, http.StatusOK)
	unrecorded := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("recorded", recorded), relyingPartyClient("unrecorded", unrecorded))
	seedSession(t, pipeline, "session-1", "bob", "recorded")

	loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline), "session-1", "recorded", "unrecorded"))

	require.Len(t, recorded.received(), 1)
	require.Empty(t, unrecorded.received())
}

func TestFailingRelyingPartyDoesNotBlockOthers(t *testing.T) {
	failing := newRelyingParty(t, http.StatusInternalServerError)
	healthy := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("failing", failing), relyingPartyClient("healthy", healthy))
	seedSession(t, pipeline, "session-1", "bob", "failing", "healthy")

	loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline), "session-1", "failing", "healthy"))

	require.Len(t, healthy.received(), 1)
	require.Len(t, failing.received(), 1)
}

func TestUnresponsiveRelyingPartyIsBoundedByTheHostClientTimeout(t *testing.T) {
	stuck := newRelyingParty(t, http.StatusOK)
	stuck.blocking(t)
	healthy := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("stuck", stuck), relyingPartyClient("healthy", healthy))
	pipeline.Root.ServerConfig().SetBackChannelLogoutHttpClient(&http.Client{Timeout: 300 * time.Millisecond})
	seedSession(t, pipeline, "session-1", "bob", "stuck", "healthy")
	frameUrl := publishLogoutContext(t, pipeline, now(pipeline), "session-1", "stuck", "healthy")

	started := time.Now()
	loadCallback(t, pipeline, frameUrl)
	require.Less(t, time.Since(started), 3*time.Second)

	require.Len(t, healthy.received(), 1)
	require.Empty(t, stuck.received())
}

func TestSessionRequiredClientReceivesSid(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	client := relyingPartyClient("rp1", rp)
	client.BackChannelLogoutSessionRequired = true
	pipeline := newSessionPipeline(client)
	seedSession(t, pipeline, "session-1", "bob", "rp1")

	loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline), "session-1", "rp1"))

	tokens := rp.received()
	require.Len(t, tokens, 1)
	_, claims := verifiedClaims(t, pipeline, tokens[0])
	require.Equal(t, "session-1", claims["sid"])
}

func TestClientWithoutBackChannelLogoutUriIsNotNotified(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("registered", rp), relyingPartyClient("unregistered", nil))
	seedSession(t, pipeline, "session-1", "bob", "unregistered", "registered")

	loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline), "session-1", "unregistered", "registered"))

	tokens := rp.received()
	require.Len(t, tokens, 1)
	_, claims := verifiedClaims(t, pipeline, tokens[0])
	require.Contains(t, []any{"registered", []any{"registered"}}, claims["aud"])
}

func TestDisabledClientIsNotNotified(t *testing.T) {
	disabled := newRelyingParty(t, http.StatusOK)
	enabled := newRelyingParty(t, http.StatusOK)
	client := relyingPartyClient("disabled", disabled)
	client.Enabled = false
	pipeline := newSessionPipeline(client, relyingPartyClient("enabled", enabled))
	seedSession(t, pipeline, "session-1", "bob", "disabled", "enabled")

	loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline), "session-1", "disabled", "enabled"))

	require.Empty(t, disabled.received())
	require.Len(t, enabled.received(), 1)
}

func TestStaleLogoutContextRendersWithoutDelivery(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("rp1", rp))
	seedSession(t, pipeline, "session-1", "bob", "rp1")

	loadCallback(t, pipeline, publishLogoutContext(t, pipeline, now(pipeline).Add(-301*time.Second), "session-1", "rp1"))

	require.Empty(t, rp.received())
}

func TestInvalidCallbackDeliversNothing(t *testing.T) {
	rp := newRelyingParty(t, http.StatusOK)
	pipeline := newSessionPipeline(relyingPartyClient("rp1", rp))
	seedSession(t, pipeline, "session-1", "bob", "rp1")
	frameUrl := publishLogoutContext(t, pipeline, now(pipeline), "session-1", "rp1")

	withoutHandle := frameUrl[:strings.Index(frameUrl, "?")]
	response, err := pipeline.BrowserClient.Get(withoutHandle)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusBadRequest, response.StatusCode)
	require.Empty(t, rp.received())
}
