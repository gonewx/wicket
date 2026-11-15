// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package discovery

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

func requestStatus(t *testing.T, pipeline *integration_common.WicketPipeline, method, path string) (int, string) {
	t.Helper()

	request, err := http.NewRequest(method, pipeline.TestServer.URL+path, nil)
	require.NoError(t, err)
	response, err := pipeline.BackChannelClient.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	_ = response.Body.Close()
	return response.StatusCode, string(body)
}

func TestAuthorizationServerMetadataEndpoint(t *testing.T) {
	t.Parallel()

	const bare = wicket.ProtocolRoutePathsAuthorizationServerMetadata

	tests := map[string]struct {
		// issuerPath is appended to the test server origin to form the
		// configured issuer; empty leaves the issuer unconfigured.
		issuerPath string
		configure  func(*config_options.WicketOptions)
		method     string
		path       string
		wantCode   int
	}{
		"default assembly":                    {method: http.MethodGet, path: bare, wantCode: http.StatusOK},
		"issuer path":                         {issuerPath: "/tenant/one", method: http.MethodGet, path: bare + "/tenant/one", wantCode: http.StatusOK},
		"issuer path with trailing slash":     {issuerPath: "/tenant/one/", method: http.MethodGet, path: bare + "/tenant/one", wantCode: http.StatusOK},
		"bare route with issuer path":         {issuerPath: "/tenant/one", method: http.MethodGet, path: bare, wantCode: http.StatusNotFound},
		"suffix without issuer path":          {method: http.MethodGet, path: bare + "/x", wantCode: http.StatusNotFound},
		"trailing slash without issuer path":  {method: http.MethodGet, path: bare + "/", wantCode: http.StatusNotFound},
		"other issuer path":                   {issuerPath: "/tenant/one", method: http.MethodGet, path: bare + "/tenant/two", wantCode: http.StatusNotFound},
		"issuer path case differs":            {issuerPath: "/tenant/one", method: http.MethodGet, path: bare + "/TENANT/one", wantCode: http.StatusNotFound},
		"route case is ignored":               {method: http.MethodGet, path: strings.ToUpper(bare), wantCode: http.StatusOK},
		"route case ignored with issuer path": {issuerPath: "/tenant/one", method: http.MethodGet, path: strings.ToUpper(bare) + "/tenant/one", wantCode: http.StatusOK},
		"non-GET":                             {method: http.MethodPost, path: bare, wantCode: http.StatusMethodNotAllowed},
		"non-GET with issuer path":            {issuerPath: "/tenant/one", method: http.MethodPost, path: bare + "/tenant/one", wantCode: http.StatusMethodNotAllowed},
		"disabled": {
			configure: func(o *config_options.WicketOptions) { o.Endpoints.EnableDiscoveryEndpoint = false },
			method:    http.MethodGet, path: bare, wantCode: http.StatusNotFound,
		},
		"disabled with issuer path": {
			issuerPath: "/tenant/one",
			configure:  func(o *config_options.WicketOptions) { o.Endpoints.EnableDiscoveryEndpoint = false },
			method:     http.MethodGet, path: bare + "/tenant/one", wantCode: http.StatusNotFound,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pipeline := newDiscoveryPipeline()
			t.Cleanup(pipeline.TestServer.Close)
			if tc.issuerPath != "" {
				pipeline.Options.IssuerUri = pipeline.TestServer.URL + tc.issuerPath
			}
			if tc.configure != nil {
				tc.configure(pipeline.Options)
			}

			code, body := requestStatus(t, pipeline, tc.method, tc.path)
			require.Equal(t, tc.wantCode, code, body)
			if code == http.StatusNotFound {
				// the handler answers with an empty body, unlike the
				// fallthrough to the test server's mux
				require.Empty(t, body)
			}
			if code != http.StatusOK {
				return
			}

			wantIssuer := pipeline.TestServer.URL + strings.TrimRight(tc.issuerPath, "/")
			require.Equal(t, wantIssuer, gjson.Get(body, "issuer").String())
			path, err := wicket.AuthorizationServerMetadataPath(wantIssuer)
			require.NoError(t, err)
			require.True(t, strings.EqualFold(path, tc.path), "served at %s, the issuer constructs %s", tc.path, path)

			configuration := fetchDiscoveryDocument(t, pipeline)
			metadata := fetchMetadataDocument(t, pipeline, tc.path)
			assertDocumentsAgree(t, configuration, metadata)
		})
	}
}

func TestAuthorizationServerMetadataLeavesOtherPathsAlone(t *testing.T) {
	t.Parallel()

	pipeline := newDiscoveryPipeline()
	t.Cleanup(pipeline.TestServer.Close)

	baseline, baselineBody := requestStatus(t, pipeline, http.MethodGet, "/no-such-route")
	require.Equal(t, http.StatusNotFound, baseline)
	require.NotEmpty(t, baselineBody)
	for _, path := range []string{
		integration_common.DiscoveryEndpoint + "/extra",
		wicket.ProtocolRoutePathsAuthorizationServerMetadata + "x",
	} {
		code, body := requestStatus(t, pipeline, http.MethodGet, path)
		require.Equalf(t, baseline, code, "%s", path)
		require.NotEmptyf(t, body, "%s does not fall through to the next handler", path)
	}
}
