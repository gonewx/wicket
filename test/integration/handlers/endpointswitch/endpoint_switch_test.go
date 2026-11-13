// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package endpointswitch

import (
	"context"
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
	config_options "github.com/gonewx/wicket/config/options"
	models_messages "github.com/gonewx/wicket/models/messages"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

const (
	secret = "secret"

	credentialsClient = "switch.credentials"
	cibaClient        = "switch.ciba"
	browserClient     = "switch.browser"
	consentClient     = "switch.consent"

	browserRedirect = "https://switch.browser/callback"
	consentRedirect = "https://switch.consent/callback"

	apiName = "api1"

	formType = "application/x-www-form-urlencoded"
	jsonType = "application/json"

	callbackEndpoint = "/connect/authorize/callback"

	cibaGrantType = "urn:openid:params:grant-type:ciba"

	consentCookiePrefix = "*messages.ConsentResponse."
)

// countingUserValidator resolves every hint to bob and counts its calls, so a
// test can tell whether a backchannel authentication request got as far as
// the host's user lookup.
type countingUserValidator struct {
	calls int
}

func (v *countingUserValidator) Validate(_ context.Context, validation *validators_models.BackchannelAuthenticationUserValidationContext) error {
	v.calls++
	validation.Subject = claimspkg.NewClaimsPrincipal(
		claimspkg.WithClaimsPrincipalIdentity(
			claimspkg.NewClaimsIdentity(
				claimspkg.WithAuthenticationType("test"),
				claimspkg.WithClaims([]*claimspkg.Claim{
					claimspkg.NewClaim(claimspkg.WithClaimType("sub"), claimspkg.WithClaimValue("bob")),
				}),
			),
		),
	)
	return nil
}

type switchFixture struct {
	*integration_common.WicketPipeline
	users *countingUserValidator
}

func secretOf(value string) []*storage_models.Secret {
	hashed := storage_models.NewSecret()
	hashed.Value = utils.Sha256(value)
	return []*storage_models.Secret{hashed}
}

func implicitClient(id string, redirect string, requireConsent bool) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	if err := client.SetAllowedGrantTypes(wicket.GrantTypesImplicit); err != nil {
		panic(err)
	}
	client.RequireConsent = requireConsent
	client.AllowedScopes = []string{"openid", "profile", apiName}
	client.RedirectUris = []string{redirect}
	client.AllowAccessTokensViaBrowser = true
	return client
}

// newSwitchPipeline assembles the real composition root with one client per
// flow this file drives. Every switch is left at its default.
func newSwitchPipeline() *switchFixture {
	users := &countingUserValidator{}
	pipeline := integration_common.NewWicketPipeline()
	pipeline.BackchannelAuthenticationUserValidator = users

	credentials := storage_models.NewClient()
	credentials.ClientId = credentialsClient
	credentials.ClientSecrets = secretOf(secret)
	if err := credentials.SetAllowedGrantTypes(wicket.GrantTypesClientCredentials); err != nil {
		panic(err)
	}
	credentials.AllowedScopes = []string{apiName}

	ciba := storage_models.NewClient()
	ciba.ClientId = cibaClient
	ciba.ClientSecrets = secretOf(secret)
	if err := ciba.SetAllowedGrantTypes(wicket.GrantTypesBackchannelAuthentication); err != nil {
		panic(err)
	}
	ciba.AllowOfflineAccess = true
	ciba.AllowedScopes = []string{"openid", "profile", apiName}

	pipeline.Clients = []*storage_models.Client{
		credentials,
		ciba,
		implicitClient(browserClient, browserRedirect, false),
		implicitClient(consentClient, consentRedirect, true),
	}

	resource := storage_models.NewApiResource()
	resource.Name = apiName
	resource.ApiSecrets = secretOf(secret)
	resource.Scopes = []string{apiName}
	pipeline.ApiResources = append(pipeline.ApiResources, resource)

	scope := storage_models.NewApiScope()
	scope.Name = apiName
	pipeline.ApiScopes = append(pipeline.ApiScopes, scope)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes,
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
	)

	user := test.NewTestUser()
	user.SubjectId = "bob"
	user.Username = "bob"
	user.Password = "bob"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.Initialize()
	return &switchFixture{WicketPipeline: pipeline, users: users}
}

type answer struct {
	status int
	body   string
	header http.Header
}

// call describes one request. A browser call goes through the cookie-carrying
// browser client without following redirects; any other call goes through the
// back-channel client.
type call struct {
	method      string
	path        string
	contentType string
	body        string
	basicUser   string
	basicSecret string
	browser     bool
}

func (f *switchFixture) send(t *testing.T, c call) answer {
	t.Helper()

	target := c.path
	if strings.HasPrefix(target, "/") {
		target = f.TestServer.URL + target
	}
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	request, err := http.NewRequest(c.method, target, body)
	require.NoError(t, err)
	if c.contentType != "" {
		request.Header.Set("Content-Type", c.contentType)
	}
	if c.basicUser != "" {
		request.SetBasicAuth(c.basicUser, c.basicSecret)
	}

	var response *http.Response
	if c.browser {
		previous := f.BrowserClient.AllowAutoRedirect
		f.BrowserClient.AllowAutoRedirect = false
		response, err = f.BrowserClient.Do(request)
		f.BrowserClient.AllowAutoRedirect = previous
	} else {
		response, err = f.BackChannelClient.Do(request)
	}
	require.NoError(t, err)
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return answer{status: response.StatusCode, body: string(raw), header: response.Header}
}

func (f *switchFixture) discovery(t *testing.T) string {
	t.Helper()
	got := f.send(t, call{method: http.MethodGet, path: integration_common.DiscoveryEndpoint})
	require.Equal(t, http.StatusOK, got.status, "discovery: %s", got.body)
	return got.body
}

func (f *switchFixture) authorizeQuery(t *testing.T, clientId string, redirect string) string {
	t.Helper()
	target, err := f.CreateAuthorizeUrl(&integration_common.AuthorizeUrl{
		ClientId:     clientId,
		ResponseType: "id_token",
		Scope:        "openid",
		RedirectUri:  redirect,
		State:        "switch_state",
		Nonce:        "switch_nonce",
	})
	require.NoError(t, err)
	return target.RawQuery
}

// requireNotFound asserts the shape of a switched-off endpoint's answer: 404,
// an empty body, neither a challenge nor a redirect, and no cache directives.
func requireNotFound(t *testing.T, got answer) {
	t.Helper()
	require.Equal(t, http.StatusNotFound, got.status, "body: %s", got.body)
	require.Empty(t, got.body)
	require.Empty(t, got.header.Values("WWW-Authenticate"))
	require.Empty(t, got.header.Values("Location"))
	require.Empty(t, got.header.Values("Content-Type"))
	require.Empty(t, got.header.Values("Cache-Control"))
	require.Empty(t, got.header.Values("Pragma"))
}

func advertisedGrantTypes(document string) []string {
	grantTypes := make([]string, 0)
	for _, value := range gjson.Get(document, "grant_types_supported").Array() {
		grantTypes = append(grantTypes, value.String())
	}
	return grantTypes
}

// probe is one request together with what it answers while the switch is on.
type probe struct {
	name       string
	call       call
	openStatus int
	// open runs further assertions on the answer given while the switch is on.
	open func(t *testing.T, got answer)
}

// runProbes sends every probe twice through the same pipeline: once with the
// switch on, asserting the usual answer, and once with it off, asserting 404.
// The switch is left on afterwards.
func runProbes(t *testing.T, fixture *switchFixture, enabled *bool, probes []probe) {
	t.Helper()
	for _, p := range probes {
		t.Run(p.name, func(t *testing.T) {
			*enabled = true
			open := fixture.send(t, p.call)
			require.Equal(t, p.openStatus, open.status, "switch on: %s", open.body)
			if p.open != nil {
				p.open(t, open)
			}

			*enabled = false
			defer func() { *enabled = true }()
			requireNotFound(t, fixture.send(t, p.call))
		})
	}
}

func credentialsForm() string {
	return url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {credentialsClient},
		"client_secret": {secret},
		"scope":         {apiName},
	}.Encode()
}

func cibaForm() string {
	return url.Values{
		"client_id":     {cibaClient},
		"client_secret": {secret},
		"scope":         {"openid profile " + apiName},
		"login_hint":    {"this means bob"},
	}.Encode()
}

func TestTokenEndpointSwitch(t *testing.T) {
	fixture := newSwitchPipeline()
	enabled := &fixture.Options.Endpoints.EnableTokenEndpoint
	path := integration_common.TokenEndpoint

	runProbes(t, fixture, enabled, []probe{
		{
			name:       "client credentials request",
			call:       call{method: http.MethodPost, path: path, contentType: formType, body: credentialsForm()},
			openStatus: http.StatusOK,
			open: func(t *testing.T, got answer) {
				require.NotEmpty(t, gjson.Get(got.body, "access_token").String(), "token: %s", got.body)
			},
		},
		{name: "GET", call: call{method: http.MethodGet, path: path}, openStatus: http.StatusBadRequest},
		{name: "POST JSON", call: call{method: http.MethodPost, path: path, contentType: jsonType, body: `{"grant_type":"client_credentials"}`}, openStatus: http.StatusBadRequest},
		{name: "POST form without credentials", call: call{method: http.MethodPost, path: path, contentType: formType, body: "grant_type=client_credentials"}, openStatus: http.StatusBadRequest},
		{
			name:       "wrong secret in Basic header",
			call:       call{method: http.MethodPost, path: path, contentType: formType, body: "grant_type=client_credentials", basicUser: credentialsClient, basicSecret: "wrong"},
			openStatus: http.StatusBadRequest,
			open: func(t *testing.T, got answer) {
				require.Equal(t, "invalid_client", gjson.Get(got.body, "error").String(), "token: %s", got.body)
			},
		},
	})

	t.Run("discovery", func(t *testing.T) {
		*enabled = true
		require.Equal(t, fixture.TestServer.URL+path, gjson.Get(fixture.discovery(t), "token_endpoint").String())

		*enabled = false
		defer func() { *enabled = true }()
		document := fixture.discovery(t)
		require.False(t, gjson.Get(document, "token_endpoint").Exists(), "discovery: %s", document)
	})
}

func TestIntrospectionEndpointSwitch(t *testing.T) {
	fixture := newSwitchPipeline()
	enabled := &fixture.Options.Endpoints.EnableIntrospectionEndpoint
	path := integration_common.IntrospectionEndpoint

	issued := fixture.send(t, call{method: http.MethodPost, path: integration_common.TokenEndpoint, contentType: formType, body: credentialsForm()})
	require.Equal(t, http.StatusOK, issued.status, "token: %s", issued.body)
	token := gjson.Get(issued.body, "access_token").String()
	require.NotEmpty(t, token)
	form := url.Values{"token": {token}}.Encode()

	runProbes(t, fixture, enabled, []probe{
		{
			name:       "authenticated request",
			call:       call{method: http.MethodPost, path: path, contentType: formType, body: form, basicUser: apiName, basicSecret: secret},
			openStatus: http.StatusOK,
			open: func(t *testing.T, got answer) {
				require.True(t, gjson.Get(got.body, "active").Exists(), "introspection: %s", got.body)
			},
		},
		{name: "GET", call: call{method: http.MethodGet, path: path}, openStatus: http.StatusMethodNotAllowed},
		{name: "POST JSON", call: call{method: http.MethodPost, path: path, contentType: jsonType, body: `{"token":"opaque"}`, basicUser: apiName, basicSecret: secret}, openStatus: http.StatusUnsupportedMediaType},
		{name: "POST form without credentials", call: call{method: http.MethodPost, path: path, contentType: formType, body: form}, openStatus: http.StatusUnauthorized},
	})

	t.Run("discovery", func(t *testing.T) {
		*enabled = true
		require.Equal(t, fixture.TestServer.URL+path, gjson.Get(fixture.discovery(t), "introspection_endpoint").String())

		*enabled = false
		defer func() { *enabled = true }()
		document := fixture.discovery(t)
		require.False(t, gjson.Get(document, "introspection_endpoint").Exists(), "discovery: %s", document)
	})
}

func TestBackchannelAuthenticationEndpointSwitch(t *testing.T) {
	fixture := newSwitchPipeline()
	enabled := &fixture.Options.Endpoints.EnableBackchannelAuthenticationEndpoint
	path := integration_common.BackchannelAuthenticationEndpoint

	t.Run("authentication request reaches the user validator only while on", func(t *testing.T) {
		request := call{method: http.MethodPost, path: path, contentType: formType, body: cibaForm()}

		*enabled = true
		open := fixture.send(t, request)
		require.Equal(t, http.StatusOK, open.status, "switch on: %s", open.body)
		require.NotEmpty(t, gjson.Get(open.body, "auth_req_id").String(), "ciba: %s", open.body)
		require.Equal(t, 1, fixture.users.calls)

		*enabled = false
		defer func() { *enabled = true }()
		requireNotFound(t, fixture.send(t, request))
		require.Equal(t, 1, fixture.users.calls, "a switched-off endpoint called the user validator")
	})

	runProbes(t, fixture, enabled, []probe{
		{name: "GET", call: call{method: http.MethodGet, path: path}, openStatus: http.StatusBadRequest},
		{name: "POST JSON", call: call{method: http.MethodPost, path: path, contentType: jsonType, body: `{"scope":"openid"}`}, openStatus: http.StatusBadRequest},
		{name: "POST form without credentials", call: call{method: http.MethodPost, path: path, contentType: formType, body: "scope=openid&login_hint=bob"}, openStatus: http.StatusBadRequest},
	})

	t.Run("discovery", func(t *testing.T) {
		*enabled = true
		document := fixture.discovery(t)
		require.Equal(t, fixture.TestServer.URL+path, gjson.Get(document, "backchannel_authentication_endpoint").String())
		require.True(t, gjson.Get(document, "backchannel_token_delivery_modes_supported").Exists(), "discovery: %s", document)
		require.True(t, gjson.Get(document, "backchannel_user_code_parameter_supported").Exists(), "discovery: %s", document)
		require.Contains(t, advertisedGrantTypes(document), cibaGrantType)

		*enabled = false
		defer func() { *enabled = true }()
		document = fixture.discovery(t)
		require.False(t, gjson.Get(document, "backchannel_authentication_endpoint").Exists(), "discovery: %s", document)
		require.False(t, gjson.Get(document, "backchannel_token_delivery_modes_supported").Exists(), "discovery: %s", document)
		require.False(t, gjson.Get(document, "backchannel_user_code_parameter_supported").Exists(), "discovery: %s", document)
		require.NotContains(t, advertisedGrantTypes(document), cibaGrantType)
	})
}

// One switch governs both the authorize route and its callback route: every
// 404 below comes from setting EnableAuthorizeEndpoint alone.
func TestAuthorizeEndpointSwitchGovernsBothRoutes(t *testing.T) {
	fixture := newSwitchPipeline()
	enabled := &fixture.Options.Endpoints.EnableAuthorizeEndpoint
	require.NoError(t, fixture.Login("bob"))

	query := fixture.authorizeQuery(t, browserClient, browserRedirect)
	authorize := integration_common.AuthorizeEndpoint

	runProbes(t, fixture, enabled, []probe{
		{
			name:       "authorize GET for a signed-in user",
			call:       call{method: http.MethodGet, path: authorize + "?" + query, browser: true},
			openStatus: http.StatusFound,
			open: func(t *testing.T, got answer) {
				require.True(t, strings.HasPrefix(got.header.Get("Location"), browserRedirect), "Location: %s", got.header.Get("Location"))
			},
		},
		{name: "authorize POST form", call: call{method: http.MethodPost, path: authorize, contentType: formType, body: query, browser: true}, openStatus: http.StatusFound},
		{name: "authorize POST JSON", call: call{method: http.MethodPost, path: authorize, contentType: jsonType, body: `{"client_id":"switch.browser"}`, browser: true}, openStatus: http.StatusUnsupportedMediaType},
		{name: "authorize PUT", call: call{method: http.MethodPut, path: authorize, browser: true}, openStatus: http.StatusUnsupportedMediaType},
		{name: "callback GET", call: call{method: http.MethodGet, path: callbackEndpoint + "?" + query, browser: true}, openStatus: http.StatusFound},
		{name: "callback POST", call: call{method: http.MethodPost, path: callbackEndpoint + "?" + query, browser: true}, openStatus: http.StatusMethodNotAllowed},
	})

	t.Run("both routes are not found under one setting", func(t *testing.T) {
		*enabled = false
		defer func() { *enabled = true }()
		requireNotFound(t, fixture.send(t, call{method: http.MethodGet, path: authorize + "?" + query, browser: true}))
		requireNotFound(t, fixture.send(t, call{method: http.MethodGet, path: callbackEndpoint + "?" + query, browser: true}))
	})
}

// With redirects followed, an anonymous user's authorize request ends on the
// host's login page; a switched-off endpoint never sends the browser there.
func TestAuthorizeEndpointSwitchKeepsAnonymousUserFromLoginPage(t *testing.T) {
	fixture := newSwitchPipeline()
	enabled := &fixture.Options.Endpoints.EnableAuthorizeEndpoint
	target := fixture.TestServer.URL + integration_common.AuthorizeEndpoint + "?" + fixture.authorizeQuery(t, browserClient, browserRedirect)

	*enabled = false
	response, err := fixture.BrowserClient.Get(target)
	require.NoError(t, err)
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	requireNotFound(t, answer{status: response.StatusCode, body: string(raw), header: response.Header})
	require.False(t, fixture.LoginWasCalled, "a switched-off endpoint sent the browser to the login page")

	*enabled = true
	response, err = fixture.BrowserClient.Get(target)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.NotEqual(t, http.StatusNotFound, response.StatusCode)
	require.True(t, fixture.LoginWasCalled)
}

func TestAuthorizeEndpointSwitchDiscovery(t *testing.T) {
	keys := []string{"authorization_endpoint", "request_parameter_supported", "request_object_signing_alg_values_supported"}

	t.Run("default request object settings", func(t *testing.T) {
		fixture := newSwitchPipeline()
		enabled := &fixture.Options.Endpoints.EnableAuthorizeEndpoint

		document := fixture.discovery(t)
		require.Equal(t, fixture.TestServer.URL+integration_common.AuthorizeEndpoint, gjson.Get(document, "authorization_endpoint").String())
		for _, key := range keys {
			require.True(t, gjson.Get(document, key).Exists(), "%s missing: %s", key, document)
		}

		*enabled = false
		document = fixture.discovery(t)
		for _, key := range keys {
			require.False(t, gjson.Get(document, key).Exists(), "%s present: %s", key, document)
		}
	})

	t.Run("with request_uri enabled", func(t *testing.T) {
		fixture := newSwitchPipeline()
		fixture.Options.Endpoints.EnableJwtRequestUri = true
		enabled := &fixture.Options.Endpoints.EnableAuthorizeEndpoint

		document := fixture.discovery(t)
		require.True(t, gjson.Get(document, "request_uri_parameter_supported").Exists(), "discovery: %s", document)
		for _, key := range keys {
			require.True(t, gjson.Get(document, key).Exists(), "%s missing: %s", key, document)
		}

		*enabled = false
		document = fixture.discovery(t)
		require.False(t, gjson.Get(document, "request_uri_parameter_supported").Exists(), "discovery: %s", document)
		for _, key := range keys {
			require.False(t, gjson.Get(document, key).Exists(), "%s present: %s", key, document)
		}
	})
}

// setCookieNamed returns the raw Set-Cookie values of a response that address
// the named cookie.
func setCookieNamed(header http.Header, name string) []string {
	matching := make([]string, 0)
	for _, value := range header.Values("Set-Cookie") {
		if strings.HasPrefix(value, name+"=") {
			matching = append(matching, value)
		}
	}
	return matching
}

// A callback consumes the stored consent answer by clearing its cookie. While
// the authorize switch is off the callback answers 404 and must leave that
// cookie alone: the observable difference is whether the response carries a
// Set-Cookie that expires it.
func TestAuthorizeCallbackSwitchedOffLeavesConsentMessageInPlace(t *testing.T) {
	fixture := newSwitchPipeline()
	enabled := &fixture.Options.Endpoints.EnableAuthorizeEndpoint
	require.NoError(t, fixture.Login("bob"))

	consent := models_messages.NewConsentResponse()
	consent.ScopesValuesConsented = []string{"openid"}
	fixture.ConsentResponse = consent

	// Stop on the consent page's own redirect: it points at the callback and
	// writes the consent answer cookie.
	fixture.BrowserClient.StopRedirectingAfter = 1
	target := fixture.TestServer.URL + integration_common.AuthorizeEndpoint + "?" + fixture.authorizeQuery(t, consentClient, consentRedirect)
	response, err := fixture.BrowserClient.Get(target)
	require.NoError(t, err)
	_ = response.Body.Close()
	require.Equal(t, http.StatusFound, response.StatusCode)
	require.True(t, fixture.ConsentWasCalled)

	location := response.Header.Get("Location")
	require.True(t, strings.HasPrefix(location, callbackEndpoint), "Location: %s", location)

	cookieName := ""
	for _, value := range response.Header.Values("Set-Cookie") {
		if strings.HasPrefix(value, consentCookiePrefix) {
			cookieName, _, _ = strings.Cut(value, "=")
		}
	}
	require.NotEmpty(t, cookieName, "consent page set no consent answer cookie: %v", response.Header.Values("Set-Cookie"))

	callback := call{method: http.MethodGet, path: location, browser: true}

	*enabled = false
	closed := fixture.send(t, callback)
	requireNotFound(t, closed)
	require.Empty(t, setCookieNamed(closed.header, cookieName), "a switched-off callback touched the consent answer cookie")

	*enabled = true
	open := fixture.send(t, callback)
	require.Equal(t, http.StatusFound, open.status, "switch on: %s", open.body)
	require.True(t, strings.HasPrefix(open.header.Get("Location"), consentRedirect), "Location: %s", open.header.Get("Location"))

	cleared := setCookieNamed(open.header, cookieName)
	require.Len(t, cleared, 1, "Set-Cookie: %v", open.header.Values("Set-Cookie"))
	parsed, err := http.ParseSetCookie(cleared[0])
	require.NoError(t, err)
	require.Equal(t, ".", parsed.Value)
	require.False(t, parsed.Expires.IsZero(), "Set-Cookie: %s", cleared[0])
	require.True(t, parsed.Expires.Before(time.Now()), "Set-Cookie: %s", cleared[0])
}

// switchedGroup is the set of routes one switch governs, with a request per
// route whose answer does not depend on any client or user.
type switchedGroup struct {
	name     string
	toggle   func(endpoints *config_options.EndpointsOptions, on bool)
	key      string
	keyPath  string
	requests []probe
}

func switchedGroups() []switchedGroup {
	return []switchedGroup{
		{
			name:    "EnableAuthorizeEndpoint",
			toggle:  func(endpoints *config_options.EndpointsOptions, on bool) { endpoints.EnableAuthorizeEndpoint = on },
			key:     "authorization_endpoint",
			keyPath: integration_common.AuthorizeEndpoint,
			requests: []probe{
				{name: "authorize POST JSON", call: call{method: http.MethodPost, path: integration_common.AuthorizeEndpoint, contentType: jsonType, body: `{}`}, openStatus: http.StatusUnsupportedMediaType},
				{name: "callback POST", call: call{method: http.MethodPost, path: callbackEndpoint}, openStatus: http.StatusMethodNotAllowed},
			},
		},
		{
			name:    "EnableTokenEndpoint",
			toggle:  func(endpoints *config_options.EndpointsOptions, on bool) { endpoints.EnableTokenEndpoint = on },
			key:     "token_endpoint",
			keyPath: integration_common.TokenEndpoint,
			requests: []probe{
				{name: "token POST form without credentials", call: call{method: http.MethodPost, path: integration_common.TokenEndpoint, contentType: formType, body: "grant_type=client_credentials"}, openStatus: http.StatusBadRequest},
			},
		},
		{
			name:    "EnableIntrospectionEndpoint",
			toggle:  func(endpoints *config_options.EndpointsOptions, on bool) { endpoints.EnableIntrospectionEndpoint = on },
			key:     "introspection_endpoint",
			keyPath: integration_common.IntrospectionEndpoint,
			requests: []probe{
				{name: "introspection GET", call: call{method: http.MethodGet, path: integration_common.IntrospectionEndpoint}, openStatus: http.StatusMethodNotAllowed},
			},
		},
		{
			name: "EnableBackchannelAuthenticationEndpoint",
			toggle: func(endpoints *config_options.EndpointsOptions, on bool) {
				endpoints.EnableBackchannelAuthenticationEndpoint = on
			},
			key:     "backchannel_authentication_endpoint",
			keyPath: integration_common.BackchannelAuthenticationEndpoint,
			requests: []probe{
				{name: "ciba POST form without credentials", call: call{method: http.MethodPost, path: integration_common.BackchannelAuthenticationEndpoint, contentType: formType, body: "scope=openid"}, openStatus: http.StatusBadRequest},
			},
		},
	}
}

func TestSwitchingOneEndpointOffLeavesTheOthersServing(t *testing.T) {
	groups := switchedGroups()
	for _, off := range groups {
		t.Run("only "+off.name+" off", func(t *testing.T) {
			fixture := newSwitchPipeline()
			off.toggle(fixture.Options.Endpoints, false)
			document := fixture.discovery(t)

			for _, group := range groups {
				if group.name == off.name {
					require.False(t, gjson.Get(document, group.key).Exists(), "%s present: %s", group.key, document)
					for _, request := range group.requests {
						requireNotFound(t, fixture.send(t, request.call))
					}
					continue
				}
				require.Equal(t, fixture.TestServer.URL+group.keyPath, gjson.Get(document, group.key).String(), "%s: %s", group.key, document)
				for _, request := range group.requests {
					got := fixture.send(t, request.call)
					require.Equal(t, request.openStatus, got.status, "%s with only %s off: %s", request.name, off.name, got.body)
				}
			}

			// The same pipeline with the switch back on: the group that was
			// off answers and is advertised like the others.
			off.toggle(fixture.Options.Endpoints, true)
			document = fixture.discovery(t)
			require.Equal(t, fixture.TestServer.URL+off.keyPath, gjson.Get(document, off.key).String(), "%s: %s", off.key, document)
			for _, request := range off.requests {
				got := fixture.send(t, request.call)
				require.Equal(t, request.openStatus, got.status, "%s with every switch on: %s", request.name, got.body)
			}
		})
	}
}

// Known limitation, to be fixed in the discovery filter: the filter keeps a
// host's custom entry by where its value points and does not look at the
// endpoint switch. With an endpoint switched off, a custom entry under the
// endpoint's own key that points back at this server's route therefore stays
// in the document although the route answers 404. Update this test together
// with the filter.
func TestEndpointSwitchKnownLimitationSwitchedOffCustomEndpointEntryIsStillAdvertised(t *testing.T) {
	for _, group := range switchedGroups() {
		for name, entry := range map[string]func(fixture *switchFixture) string{
			"relative path": func(*switchFixture) string { return "~" + group.keyPath },
			"absolute URL":  func(fixture *switchFixture) string { return fixture.TestServer.URL + group.keyPath },
		} {
			t.Run(group.key+"/"+name, func(t *testing.T) {
				fixture := newSwitchPipeline()
				request := call{method: http.MethodPost, path: "", contentType: formType}

				// Switch on: the route serves, and the document carries the
				// generated value.
				document := fixture.discovery(t)
				generated := gjson.Get(document, group.key)
				require.Equal(t, fixture.TestServer.URL+group.keyPath, generated.String(), "discovery: %s", document)
				request.path = generated.String()
				require.NotEqual(t, http.StatusNotFound, fixture.send(t, request).status)

				group.toggle(fixture.Options.Endpoints, false)
				fixture.Options.Discovery.CustomEntries[group.key] = entry(fixture)

				document = fixture.discovery(t)
				advertised := gjson.Get(document, group.key)
				require.True(t, advertised.Exists(), "discovery: %s", document)
				require.Equal(t, fixture.TestServer.URL+group.keyPath, advertised.String())

				request.path = advertised.String()
				requireNotFound(t, fixture.send(t, request))
			})
		}
	}
}

// Known limitation, to be fixed in the discovery filter: the filter has no
// rule for the capability keys that the generator writes only while the
// authorize or backchannel authentication endpoint is on. With the endpoint
// switched off, a host's custom entries under those keys therefore enter the
// document. Update this test together with the filter.
func TestEndpointSwitchKnownLimitationSwitchedOffCustomCapabilityEntriesAreStillAdvertised(t *testing.T) {
	for name, tt := range map[string]struct {
		toggle  func(endpoints *config_options.EndpointsOptions)
		entries map[string]any
	}{
		"authorize": {
			toggle: func(endpoints *config_options.EndpointsOptions) { endpoints.EnableAuthorizeEndpoint = false },
			entries: map[string]any{
				"request_parameter_supported":                 true,
				"request_object_signing_alg_values_supported": []string{"RS256"},
			},
		},
		"backchannel authentication": {
			toggle: func(endpoints *config_options.EndpointsOptions) {
				endpoints.EnableBackchannelAuthenticationEndpoint = false
			},
			entries: map[string]any{
				"backchannel_token_delivery_modes_supported": []string{"poll"},
				"backchannel_user_code_parameter_supported":  true,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSwitchPipeline()

			// Switch on: the generator writes every one of these keys.
			document := fixture.discovery(t)
			for key := range tt.entries {
				require.True(t, gjson.Get(document, key).Exists(), "%s missing: %s", key, document)
			}

			// Switch off, without custom entries: the keys are absent.
			tt.toggle(fixture.Options.Endpoints)
			document = fixture.discovery(t)
			for key := range tt.entries {
				require.False(t, gjson.Get(document, key).Exists(), "%s present: %s", key, document)
			}

			for key, value := range tt.entries {
				fixture.Options.Discovery.CustomEntries[key] = value
			}
			document = fixture.discovery(t)
			for key := range tt.entries {
				require.True(t, gjson.Get(document, key).Exists(), "%s missing: %s", key, document)
			}
		})
	}
}
