// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package protocol

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	integration_common "github.com/gonewx/wicket/test/integration/common"
)

// Each endpoint accepts only its protocol-defined HTTP methods; every other
// method must be answered with 405 rather than a protocol error body.
func TestEndpointsRejectUnsupportedHttpMethods(t *testing.T) {
	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()

	cases := map[string]struct {
		path   string
		method string
	}{
		"discovery rejects POST":             {path: integration_common.DiscoveryEndpoint, method: http.MethodPost},
		"discovery rejects DELETE":           {path: integration_common.DiscoveryEndpoint, method: http.MethodDelete},
		"jwks rejects POST":                  {path: integration_common.DiscoveryKeysEndpoint, method: http.MethodPost},
		"checksession rejects POST":          {path: integration_common.CheckSessionEndpoint, method: http.MethodPost},
		"introspection rejects GET":          {path: integration_common.IntrospectionEndpoint, method: http.MethodGet},
		"introspection rejects PUT":          {path: integration_common.IntrospectionEndpoint, method: http.MethodPut},
		"revocation rejects GET":             {path: integration_common.RevocationEndpoint, method: http.MethodGet},
		"revocation rejects PUT":             {path: integration_common.RevocationEndpoint, method: http.MethodPut},
		"endsession rejects DELETE":          {path: integration_common.EndSessionEndpoint, method: http.MethodDelete},
		"userinfo rejects PATCH":             {path: integration_common.UserInfoEndpoint, method: http.MethodPatch},
		"endsession callback rejects DELETE": {path: integration_common.EndSessionCallbackEndpoint, method: http.MethodDelete},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			request, err := http.NewRequest(tc.method, pipeline.TestServer.URL+tc.path, nil)
			a.NoError(err)

			response, err := pipeline.BackChannelClient.Do(request)

			a.NoError(err)
			a.Equal(http.StatusMethodNotAllowed, response.StatusCode)
		})
	}
}

// The GET-only document endpoints answer their supported method with 200.
func TestDocumentEndpointsAnswerGet(t *testing.T) {
	pipeline := integration_common.NewWicketPipeline()
	pipeline.Initialize()

	cases := map[string]string{
		"discovery document": integration_common.DiscoveryEndpoint,
		"jwks document":      integration_common.DiscoveryKeysEndpoint,
		"checksession page":  integration_common.CheckSessionEndpoint,
	}

	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)

			response, err := pipeline.BackChannelClient.Get(pipeline.TestServer.URL + path)

			a.NoError(err)
			a.Equal(http.StatusOK, response.StatusCode)
		})
	}
}
