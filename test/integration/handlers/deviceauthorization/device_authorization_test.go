// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package deviceauthorization

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/test"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/utils"
)

const (
	deviceClient       = "device.client"
	publicDeviceClient = "device.public"
	shortLivedClient   = "device.short"
	codeClient         = "code.client"
	secret             = "secret"
	subjectId          = "1"
	pollingInterval    = 5
)

func newClient(id string, grantTypes []string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	client.ClientName = "Device " + id
	clientSecret := storage_models.NewSecret()
	clientSecret.Value = utils.Sha256(secret)
	client.ClientSecrets = []*storage_models.Secret{clientSecret}
	if err := client.SetAllowedGrantTypes(grantTypes); err != nil {
		panic(err)
	}
	client.AllowedScopes = []string{"openid", "profile", "api1"}
	client.AllowOfflineAccess = true
	return client
}

// newDevicePipeline assembles the default composition root with device flow
// clients and the polling interval a host configures.
func newDevicePipeline() *integration_common.WicketPipeline {
	pipeline := integration_common.NewWicketPipeline()

	public := newClient(publicDeviceClient, wicket.GrantTypesDeviceFlow)
	public.ClientSecrets = nil
	public.RequireClientSecret = false
	shortLived := newClient(shortLivedClient, wicket.GrantTypesDeviceFlow)
	shortLived.DeviceCodeLifetime = 1
	pipeline.Clients = append(pipeline.Clients,
		newClient(deviceClient, wicket.GrantTypesDeviceFlow),
		public,
		shortLived,
		newClient(codeClient, wicket.GrantTypesCode),
	)

	pipeline.IdentityScopes = append(pipeline.IdentityScopes,
		storage_models.IdentityResourcesOpenId(),
		storage_models.IdentityResourcesProfile(),
	)
	resource := storage_models.NewApiResource()
	resource.Name = "api1"
	resource.Scopes = []string{"api1"}
	pipeline.ApiResources = append(pipeline.ApiResources, resource)
	scope := storage_models.NewApiScope()
	scope.Name = "api1"
	pipeline.ApiScopes = append(pipeline.ApiScopes, scope)

	user := test.NewTestUser()
	user.SubjectId = subjectId
	user.Username = "bob"
	user.Password = "bob"
	pipeline.Users = append(pipeline.Users, user)

	pipeline.Initialize()
	pipeline.Options.DeviceFlow.Interval = pollingInterval
	return pipeline
}

type answer struct {
	status int
	header http.Header
	body   string
}

func (a answer) json(path string) gjson.Result {
	return gjson.Get(a.body, path)
}

type deviceCall struct {
	method      string
	form        url.Values
	basicClient string
	basicSecret string
	contentType string
}

func call(t *testing.T, pipeline *integration_common.WicketPipeline, path string, c deviceCall) answer {
	t.Helper()
	method := c.method
	if method == "" {
		method = http.MethodPost
	}
	request, err := http.NewRequest(method, pipeline.TestServer.URL+path, strings.NewReader(c.form.Encode()))
	require.NoError(t, err)
	contentType := c.contentType
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	request.Header.Set("Content-Type", contentType)
	if c.basicClient != "" {
		request.SetBasicAuth(c.basicClient, c.basicSecret)
	}
	response, err := pipeline.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return answer{status: response.StatusCode, header: response.Header, body: string(body)}
}

// authorizeDevice asks the device authorization endpoint for codes on behalf
// of clientId, authenticating with the secret in the body.
func authorizeDevice(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string, scope string) answer {
	t.Helper()
	form := url.Values{"client_id": {clientId}, "client_secret": {secret}}
	if scope != "" {
		form.Set("scope", scope)
	}
	got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: form})
	require.Equal(t, http.StatusOK, got.status, "device authorization: %s", got.body)
	require.NotEmpty(t, got.json("device_code").String())
	require.NotEmpty(t, got.json("user_code").String())
	return got
}

func poll(t *testing.T, pipeline *integration_common.WicketPipeline, clientId string, deviceCode string) answer {
	t.Helper()
	return call(t, pipeline, integration_common.TokenEndpoint, deviceCall{form: url.Values{
		"grant_type":    {wicket.GrantTypeDeviceCode},
		"client_id":     {clientId},
		"client_secret": {secret},
		"device_code":   {deviceCode},
	}})
}

func requirePollError(t *testing.T, got answer, errorCode string) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, got.status, "token endpoint: %s", got.body)
	require.Equal(t, errorCode, got.json("error").String(), "token endpoint: %s", got.body)
}

func requireJsonError(t *testing.T, got answer, status int, errorCode string) {
	t.Helper()
	require.Equal(t, status, got.status, "device authorization: %s", got.body)
	require.Equal(t, "application/json", got.header.Get("Content-Type"))
	require.Equal(t, errorCode, got.json("error").String(), "device authorization: %s", got.body)
}

func requireNoCache(t *testing.T, got answer) {
	t.Helper()
	cacheControl := strings.Join(got.header.Values("Cache-Control"), ",")
	require.Contains(t, cacheControl, "no-store")
	require.Contains(t, cacheControl, "no-cache")
	require.Equal(t, "no-cache", got.header.Get("Pragma"))
}

// interaction resolves the host-facing interaction service from a request
// scope, as a verification page would.
func interaction(t *testing.T, pipeline *integration_common.WicketPipeline) services.DeviceFlowInteractionService {
	t.Helper()
	scope := pipeline.Root.CreateScope()
	t.Cleanup(func() { _ = scope.Close() })
	return godi.GetRequired[services.DeviceFlowInteractionService](scope)
}

func signedInUser(t *testing.T) *claimspkg.ClaimsPrincipal {
	t.Helper()
	principal, err := models.NewLocalUser(models.WithLocalUserSubjectId(subjectId)).CreatePrincipal()
	require.NoError(t, err)
	return principal
}

func scopeSet(value string) []string {
	scopes := strings.Fields(value)
	slices.Sort(scopes)
	return scopes
}

func TestDeviceAuthorizationRequestShape(t *testing.T) {
	pipeline := newDevicePipeline()

	t.Run("GET is not allowed", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{method: http.MethodGet})
		require.Equal(t, http.StatusMethodNotAllowed, got.status)
	})

	t.Run("JSON body is unsupported", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{contentType: "application/json", basicClient: deviceClient, basicSecret: secret})
		require.Equal(t, http.StatusUnsupportedMediaType, got.status)
	})
}

func TestDeviceAuthorizationClientAuthentication(t *testing.T) {
	pipeline := newDevicePipeline()

	t.Run("wrong secret in Basic header is 401 with a challenge", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"scope": {"api1"}}, basicClient: deviceClient, basicSecret: "wrong"})
		requireJsonError(t, got, http.StatusUnauthorized, "invalid_client")
		require.Equal(t, `Basic realm="wicket"`, got.header.Get("WWW-Authenticate"))
	})

	t.Run("wrong secret in body is 400", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {deviceClient}, "client_secret": {"wrong"}}})
		requireJsonError(t, got, http.StatusBadRequest, "invalid_client")
		require.Empty(t, got.header.Get("WWW-Authenticate"))
	})

	t.Run("unknown client is 400", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {"nobody"}}})
		requireJsonError(t, got, http.StatusBadRequest, "invalid_client")
	})

	t.Run("no credentials is 400", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"scope": {"api1"}}})
		requireJsonError(t, got, http.StatusBadRequest, "invalid_client")
	})
}

func TestDeviceAuthorizationProtocolErrors(t *testing.T) {
	pipeline := newDevicePipeline()

	t.Run("client without the device code grant is unauthorized_client", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {codeClient}, "client_secret": {secret}}})
		requireJsonError(t, got, http.StatusBadRequest, "unauthorized_client")
		requireNoCache(t, got)
	})

	t.Run("unknown scope is invalid_scope", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {deviceClient}, "client_secret": {secret}, "scope": {"openid unknown"}}})
		requireJsonError(t, got, http.StatusBadRequest, "invalid_scope")
		requireNoCache(t, got)
	})

	t.Run("identity scope without openid is invalid_scope", func(t *testing.T) {
		got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {deviceClient}, "client_secret": {secret}, "scope": {"profile"}}})
		requireJsonError(t, got, http.StatusBadRequest, "invalid_scope")
	})
}

func TestDeviceAuthorizationSuccess(t *testing.T) {
	pipeline := newDevicePipeline()

	requireIssued := func(t *testing.T, got answer) {
		t.Helper()
		require.Equal(t, http.StatusOK, got.status, "device authorization: %s", got.body)
		require.Equal(t, "application/json", got.header.Get("Content-Type"))
		requireNoCache(t, got)
		require.NotEmpty(t, got.json("device_code").String())
		require.NotEmpty(t, got.json("user_code").String())
		require.Equal(t, pipeline.TestServer.URL+"/device", got.json("verification_uri").String())
		require.Equal(t, int64(300), got.json("expires_in").Int())
		require.Equal(t, int64(pollingInterval), got.json("interval").Int())
		require.True(t, strings.HasPrefix(got.json("verification_uri_complete").String(), pipeline.TestServer.URL+"/device?"))
	}

	t.Run("confidential client with secret in the body", func(t *testing.T) {
		requireIssued(t, call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {deviceClient}, "client_secret": {secret}, "scope": {"openid api1"}}}))
	})

	t.Run("confidential client with Basic credentials", func(t *testing.T) {
		requireIssued(t, call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"scope": {"openid api1"}}, basicClient: deviceClient, basicSecret: secret}))
	})

	t.Run("public client with client_id only", func(t *testing.T) {
		requireIssued(t, call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {publicDeviceClient}}}))
	})

	t.Run("query string parameters are ignored", func(t *testing.T) {
		target := integration_common.DeviceAuthorization + "?" + url.Values{"scope": {"unknown"}}.Encode()
		requireIssued(t, call(t, pipeline, target, deviceCall{form: url.Values{"client_id": {deviceClient}, "client_secret": {secret}, "scope": {"api1"}}}))
	})

	t.Run("each request gets distinct codes", func(t *testing.T) {
		first := authorizeDevice(t, pipeline, deviceClient, "api1")
		second := authorizeDevice(t, pipeline, deviceClient, "api1")
		require.NotEqual(t, first.json("device_code").String(), second.json("device_code").String())
		require.NotEqual(t, first.json("user_code").String(), second.json("user_code").String())
	})
}

func TestDeviceFlowPollingBeforeDecision(t *testing.T) {
	pipeline := newDevicePipeline()

	t.Run("pending authorization", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, deviceClient, "openid api1")
		requirePollError(t, poll(t, pipeline, deviceClient, device.json("device_code").String()), "authorization_pending")
	})

	t.Run("polling again within the interval slows down", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, deviceClient, "openid api1")
		deviceCode := device.json("device_code").String()
		requirePollError(t, poll(t, pipeline, deviceClient, deviceCode), "authorization_pending")
		requirePollError(t, poll(t, pipeline, deviceClient, deviceCode), "slow_down")
	})

	t.Run("another client's device code is invalid_grant", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, deviceClient, "openid api1")
		requirePollError(t, poll(t, pipeline, shortLivedClient, device.json("device_code").String()), "invalid_grant")
	})

	t.Run("expired device code", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, shortLivedClient, "openid api1")
		require.Equal(t, int64(1), device.json("expires_in").Int())
		time.Sleep(1500 * time.Millisecond)
		requirePollError(t, poll(t, pipeline, shortLivedClient, device.json("device_code").String()), "expired_token")
	})
}

func TestDeviceFlowDenied(t *testing.T) {
	pipeline := newDevicePipeline()
	device := authorizeDevice(t, pipeline, deviceClient, "openid api1")

	require.NoError(t, interaction(t, pipeline).Deny(context.Background(), device.json("user_code").String()))

	requirePollError(t, poll(t, pipeline, deviceClient, device.json("device_code").String()), "access_denied")
}

func TestDeviceFlowApprovedWithNarrowedScopes(t *testing.T) {
	pipeline := newDevicePipeline()
	device := authorizeDevice(t, pipeline, deviceClient, "openid profile api1 offline_access")
	userCode := device.json("user_code").String()
	deviceCode := device.json("device_code").String()
	service := interaction(t, pipeline)

	authorization, err := service.GetAuthorizationContext(context.Background(), userCode)
	require.NoError(t, err)
	require.Equal(t, deviceClient, authorization.ClientId)
	require.Equal(t, "Device "+deviceClient, authorization.ClientName)
	require.True(t, authorization.IsOpenIdRequest)
	require.ElementsMatch(t, []string{"openid", "profile", "api1", "offline_access"}, authorization.RequestedScopes)

	approved := []string{"openid", "api1", "offline_access"}
	require.NoError(t, service.Approve(context.Background(), userCode, signedInUser(t), "", approved))

	tokens := poll(t, pipeline, deviceClient, deviceCode)
	require.Equal(t, http.StatusOK, tokens.status, "token endpoint: %s", tokens.body)
	require.Equal(t, scopeSet("api1 offline_access openid"), scopeSet(tokens.json("scope").String()))
	require.NotEmpty(t, tokens.json("access_token").String())
	require.NotEmpty(t, tokens.json("id_token").String())
	refreshToken := tokens.json("refresh_token").String()
	require.NotEmpty(t, refreshToken, "approving offline_access must issue a refresh token")

	t.Run("the device code is redeemed once", func(t *testing.T) {
		requirePollError(t, poll(t, pipeline, deviceClient, deviceCode), "invalid_grant")
	})

	t.Run("the user code cannot be handled again", func(t *testing.T) {
		_, err := service.GetAuthorizationContext(context.Background(), userCode)
		require.ErrorIs(t, err, services.ErrDeviceFlowUserCodeNotFound)
	})

	t.Run("refresh stays within the approved scopes", func(t *testing.T) {
		refreshed := call(t, pipeline, integration_common.TokenEndpoint, deviceCall{form: url.Values{
			"grant_type":    {"refresh_token"},
			"client_id":     {deviceClient},
			"client_secret": {secret},
			"refresh_token": {refreshToken},
		}})
		require.Equal(t, http.StatusOK, refreshed.status, "refresh: %s", refreshed.body)
		got := scopeSet(refreshed.json("scope").String())
		require.NotEmpty(t, got)
		for _, scope := range got {
			require.Contains(t, approved, scope, "refreshed scope %q was not approved", scope)
		}
	})
}

func TestDeviceFlowApprovedWithoutOfflineAccessIssuesNoRefreshToken(t *testing.T) {
	pipeline := newDevicePipeline()
	device := authorizeDevice(t, pipeline, deviceClient, "openid api1 offline_access")

	require.NoError(t, interaction(t, pipeline).Approve(context.Background(), device.json("user_code").String(), signedInUser(t), "", []string{"openid", "api1"}))

	tokens := poll(t, pipeline, deviceClient, device.json("device_code").String())
	require.Equal(t, http.StatusOK, tokens.status, "token endpoint: %s", tokens.body)
	require.Equal(t, scopeSet("api1 openid"), scopeSet(tokens.json("scope").String()))
	// The token response writes the refresh_token member for every grant, as
	// an empty string when no refresh token is issued.
	require.Empty(t, tokens.json("refresh_token").String(), "no refresh token without offline_access: %s", tokens.body)
}

func TestDeviceFlowInteractionServiceAgainstTheStore(t *testing.T) {
	pipeline := newDevicePipeline()
	service := interaction(t, pipeline)
	user := signedInUser(t)

	t.Run("unknown user code", func(t *testing.T) {
		require.ErrorIs(t, service.Deny(context.Background(), "000000000"), services.ErrDeviceFlowUserCodeNotFound)
	})

	t.Run("expired user code", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, shortLivedClient, "openid api1")
		time.Sleep(1500 * time.Millisecond)
		require.ErrorIs(t, service.Approve(context.Background(), device.json("user_code").String(), user, "", []string{"openid"}), services.ErrDeviceFlowUserCodeExpired)
	})

	t.Run("user code handled twice", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, deviceClient, "openid api1")
		userCode := device.json("user_code").String()
		require.NoError(t, service.Deny(context.Background(), userCode))
		require.ErrorIs(t, service.Approve(context.Background(), userCode, user, "", []string{"openid"}), services.ErrDeviceFlowUserCodeAlreadyHandled)
	})

	t.Run("handled and then expired user code reports expiry", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, shortLivedClient, "openid api1")
		userCode := device.json("user_code").String()
		require.NoError(t, service.Deny(context.Background(), userCode))
		time.Sleep(1500 * time.Millisecond)
		require.ErrorIs(t, service.Deny(context.Background(), userCode), services.ErrDeviceFlowUserCodeExpired)
	})

	t.Run("approval of a scope that was not requested", func(t *testing.T) {
		device := authorizeDevice(t, pipeline, deviceClient, "openid api1")
		require.ErrorIs(t, service.Approve(context.Background(), device.json("user_code").String(), user, "", []string{"openid", "profile"}), services.ErrDeviceFlowInvalidApproval)
	})
}

func discoveryDocument(t *testing.T, pipeline *integration_common.WicketPipeline) string {
	t.Helper()
	got := call(t, pipeline, integration_common.DiscoveryEndpoint, deviceCall{method: http.MethodGet})
	require.Equal(t, http.StatusOK, got.status)
	return got.body
}

func advertisedGrantTypes(document string) []string {
	var grantTypes []string
	for _, value := range gjson.Get(document, "grant_types_supported").Array() {
		grantTypes = append(grantTypes, value.String())
	}
	return grantTypes
}

func TestDiscoveryAdvertisesDeviceAuthorization(t *testing.T) {
	pipeline := newDevicePipeline()
	document := discoveryDocument(t, pipeline)

	require.Equal(t, pipeline.TestServer.URL+"/connect/deviceauthorization", gjson.Get(document, "device_authorization_endpoint").String())
	require.Contains(t, advertisedGrantTypes(document), wicket.GrantTypeDeviceCode)
}

func TestDeviceAuthorizationSwitchedOff(t *testing.T) {
	pipeline := newDevicePipeline()
	pipeline.Options.Endpoints.EnableDeviceAuthorizationEndpoint = false

	got := call(t, pipeline, integration_common.DeviceAuthorization, deviceCall{form: url.Values{"client_id": {deviceClient}, "client_secret": {secret}}})
	require.Equal(t, http.StatusNotFound, got.status)

	document := discoveryDocument(t, pipeline)
	require.False(t, gjson.Get(document, "device_authorization_endpoint").Exists())
	require.NotContains(t, advertisedGrantTypes(document), wicket.GrantTypeDeviceCode)
}
