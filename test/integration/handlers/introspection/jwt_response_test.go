// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package introspection

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// introspectAccepting posts an introspection request with the given Accept
// header; an empty accept sends none.
func introspectAccepting(t *testing.T, pipeline *integration_common.WicketPipeline, api string, apiSecret string, form url.Values, accept string) (*http.Response, string) {
	t.Helper()

	request, err := http.NewRequest(http.MethodPost, pipeline.TestServer.URL+integration_common.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	if api != "" {
		request.SetBasicAuth(api, apiSecret)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		request.Header.Set("Accept", accept)
	}

	response, err := pipeline.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response, string(body)
}

func discoveryDocument(t *testing.T, pipeline *integration_common.WicketPipeline) map[string]any {
	t.Helper()
	response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + integration_common.DiscoveryEndpoint)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)
	document := map[string]any{}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&document))
	return document
}

// verifiedIntrospectionJwt checks the signature against the JWKS published
// through discovery and returns the protected header typ and the payload.
func verifiedIntrospectionJwt(t *testing.T, pipeline *integration_common.WicketPipeline, token string) (string, map[string]any) {
	t.Helper()
	jwksUri, ok := discoveryDocument(t, pipeline)[wicket.DiscoveryJwksUri].(string)
	require.True(t, ok)
	response, err := pipeline.BackChannelClient.Get(jwksUri)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	set, err := jwk.Parse(body)
	require.NoError(t, err)

	_, err = jwt.Parse([]byte(token), jwt.WithKeySet(set), jwt.WithValidate(false))
	require.NoError(t, err, "the introspection response must verify against the published JWKS")

	message, err := jws.Parse([]byte(token))
	require.NoError(t, err)
	headers := message.Signatures()[0].ProtectedHeaders()
	typ, _ := headers.Type()
	alg, ok := headers.Algorithm()
	require.True(t, ok, "the introspection response carries no alg header")
	advertised, ok := discoveryDocument(t, pipeline)[wicket.DiscoveryIntrospectionSigningAlgValuesSupported].([]any)
	require.True(t, ok, "discovery does not advertise %s", wicket.DiscoveryIntrospectionSigningAlgValuesSupported)
	require.Contains(t, advertised, any(alg.String()), "alg is not among the advertised introspection signing algorithms")
	payload := map[string]any{}
	require.NoError(t, json.Unmarshal(message.Payload(), &payload))
	return typ, payload
}

func requireJwtResponse(t *testing.T, pipeline *integration_common.WicketPipeline, response *http.Response, body string) map[string]any {
	t.Helper()
	require.Equal(t, http.StatusOK, response.StatusCode, body)
	require.Equal(t, wicket.MediaTypesTokenIntrospectionJwt, response.Header.Get("Content-Type"))
	require.Equal(t, []string{"no-store", "no-cache", "max-age=0"}, response.Header.Values("Cache-Control"))
	require.Equal(t, "no-cache", response.Header.Get("Pragma"))
	require.False(t, strings.HasSuffix(body, "\n"))

	typ, payload := verifiedIntrospectionJwt(t, pipeline, body)
	require.Equal(t, wicket.JwtTypesTokenIntrospection, typ)
	require.Equal(t, []string{"aud", "iat", "iss", wicket.ClaimTypesTokenIntrospection}, slices.Sorted(maps.Keys(payload)))
	require.Equal(t, discoveryDocument(t, pipeline)[wicket.DiscoveryIssuer], payload["iss"])
	require.Equal(t, "api1", payload["aud"])
	require.IsType(t, float64(0), payload["iat"])
	introspection, ok := payload[wicket.ClaimTypesTokenIntrospection].(map[string]any)
	require.True(t, ok, "token_introspection is not an object: %v", payload[wicket.ClaimTypesTokenIntrospection])
	return introspection
}

func TestIntrospectionJwtResponseForAnActiveToken(t *testing.T) {
	for name, accept := range map[string]string{
		"exact media type":         wicket.MediaTypesTokenIntrospectionJwt,
		"among others with weight": "application/json, Application/Token-Introspection+JWT;q=0.5",
	} {
		t.Run(name, func(t *testing.T) {
			pipeline := newIntrospectionPipeline()
			token := clientCredentialsToken(t, pipeline, "client1", "api1")
			form := url.Values{"token": {token}}

			response, body := introspectAccepting(t, pipeline, "api1", "secret", form, accept)
			introspection := requireJwtResponse(t, pipeline, response, body)

			jsonResponse, jsonBody := introspectAccepting(t, pipeline, "api1", "secret", form, "")
			require.Equal(t, http.StatusOK, jsonResponse.StatusCode)
			want := map[string]any{}
			require.NoError(t, json.Unmarshal([]byte(jsonBody), &want))
			require.Equal(t, true, want["active"])
			require.Equal(t, want, introspection)
		})
	}
}

func TestIntrospectionJwtResponseForAnInactiveToken(t *testing.T) {
	pipeline := newIntrospectionPipeline()

	response, body := introspectAccepting(t, pipeline, "api1", "secret", url.Values{"token": {"invalid"}}, wicket.MediaTypesTokenIntrospectionJwt)
	introspection := requireJwtResponse(t, pipeline, response, body)
	require.Equal(t, map[string]any{"active": false}, introspection)
}

func TestIntrospectionAnswersJsonWithoutAnExplicitJwtRequest(t *testing.T) {
	for name, accept := range map[string]string{
		"no accept":    "",
		"json":         "application/json",
		"any":          "*/*",
		"quality zero": "application/token-introspection+jwt;q=0",
	} {
		t.Run(name, func(t *testing.T) {
			pipeline := newIntrospectionPipeline()
			token := clientCredentialsToken(t, pipeline, "client1", "api1")

			response, body := introspectAccepting(t, pipeline, "api1", "secret", url.Values{"token": {token}}, accept)
			require.Equal(t, http.StatusOK, response.StatusCode)
			require.Equal(t, "application/json", response.Header.Get("Content-Type"))
			require.True(t, strings.HasSuffix(body, "\n"))
			values := map[string]any{}
			require.NoError(t, json.Unmarshal([]byte(body), &values))
			require.Equal(t, true, values["active"])
		})
	}
}

func TestIntrospectionErrorsIgnoreTheJwtRequest(t *testing.T) {
	type outcome struct {
		status       int
		contentType  string
		cacheControl []string
		body         string
	}
	send := func(t *testing.T, pipeline *integration_common.WicketPipeline, method string, contentType string, api string, apiSecret string, body string, accept string) outcome {
		t.Helper()
		request, err := http.NewRequest(method, pipeline.TestServer.URL+integration_common.IntrospectionEndpoint, strings.NewReader(body))
		require.NoError(t, err)
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		if api != "" {
			request.SetBasicAuth(api, apiSecret)
		}
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
		response, err := pipeline.BackChannelClient.Do(request)
		require.NoError(t, err)
		payload, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		_ = response.Body.Close()
		return outcome{
			status:       response.StatusCode,
			contentType:  response.Header.Get("Content-Type"),
			cacheControl: response.Header.Values("Cache-Control"),
			body:         string(payload),
		}
	}
	const form = "application/x-www-form-urlencoded"

	for name, tc := range map[string]struct {
		method      string
		contentType string
		api         string
		apiSecret   string
		body        string
		switchOff   bool
		wantStatus  int
	}{
		"unauthenticated":       {method: http.MethodPost, contentType: form, body: "token=x", wantStatus: http.StatusUnauthorized},
		"wrong api secret":      {method: http.MethodPost, contentType: form, api: "api1", apiSecret: "invalid", body: "token=x", wantStatus: http.StatusUnauthorized},
		"missing token":         {method: http.MethodPost, contentType: form, api: "api1", apiSecret: "secret", wantStatus: http.StatusBadRequest},
		"not a POST":            {method: http.MethodGet, api: "api1", apiSecret: "secret", wantStatus: http.StatusMethodNotAllowed},
		"not a form":            {method: http.MethodPost, contentType: "application/json", api: "api1", apiSecret: "secret", body: "{}", wantStatus: http.StatusUnsupportedMediaType},
		"endpoint switched off": {method: http.MethodPost, contentType: form, api: "api1", apiSecret: "secret", body: "token=x", switchOff: true, wantStatus: http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			pipeline := newIntrospectionPipeline()
			if tc.switchOff {
				pipeline.Options.Endpoints.EnableIntrospectionEndpoint = false
			}
			got := send(t, pipeline, tc.method, tc.contentType, tc.api, tc.apiSecret, tc.body, wicket.MediaTypesTokenIntrospectionJwt)
			want := send(t, pipeline, tc.method, tc.contentType, tc.api, tc.apiSecret, tc.body, "")
			require.Equal(t, tc.wantStatus, got.status)
			require.Equal(t, want, got)
		})
	}
}
