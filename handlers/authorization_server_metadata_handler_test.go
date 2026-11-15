// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	config_options "github.com/gonewx/wicket/config/options"
)

func newTestDiscoveryHandler(generator *fakeDiscoveryResponseGenerator, issuer string, options *config_options.WicketOptions) *DiscoveryHandler {
	return NewDiscoveryHandler(
		generator,
		&fakeServerUrls{base: "https://wicket.test"},
		&fakeIssuerNameService{issuer: issuer},
		options,
		nil, nil, nil,
		quietLogger(),
	)
}

func TestAuthorizationServerMetadataHandlerDispatch(t *testing.T) {
	t.Parallel()

	disabled := config_options.NewWicketOptions()
	disabled.Endpoints.EnableDiscoveryEndpoint = false

	tests := map[string]struct {
		issuer   string
		options  *config_options.WicketOptions
		method   string
		path     string
		wantCode int
	}{
		"bare route without issuer path":     {issuer: "https://wicket.test", method: http.MethodGet, path: "/.well-known/oauth-authorization-server", wantCode: http.StatusOK},
		"route case is ignored":              {issuer: "https://wicket.test", method: http.MethodGet, path: "/.WELL-KNOWN/OAUTH-AUTHORIZATION-SERVER", wantCode: http.StatusOK},
		"issuer path":                        {issuer: "https://wicket.test/tenant/one", method: http.MethodGet, path: "/.well-known/oauth-authorization-server/tenant/one", wantCode: http.StatusOK},
		"issuer path with trailing slash":    {issuer: "https://wicket.test/tenant/one/", method: http.MethodGet, path: "/.well-known/oauth-authorization-server/tenant/one", wantCode: http.StatusOK},
		"escaped issuer path":                {issuer: "https://wicket.test/my%20tenant", method: http.MethodGet, path: "/.well-known/oauth-authorization-server/my%20tenant", wantCode: http.StatusOK},
		"bare route with issuer path":        {issuer: "https://wicket.test/tenant/one", method: http.MethodGet, path: "/.well-known/oauth-authorization-server", wantCode: http.StatusNotFound},
		"suffix without issuer path":         {issuer: "https://wicket.test", method: http.MethodGet, path: "/.well-known/oauth-authorization-server/x", wantCode: http.StatusNotFound},
		"trailing slash without issuer path": {issuer: "https://wicket.test", method: http.MethodGet, path: "/.well-known/oauth-authorization-server/", wantCode: http.StatusNotFound},
		"other issuer path":                  {issuer: "https://wicket.test/tenant/one", method: http.MethodGet, path: "/.well-known/oauth-authorization-server/tenant/two", wantCode: http.StatusNotFound},
		"issuer path case differs":           {issuer: "https://wicket.test/tenant/one", method: http.MethodGet, path: "/.well-known/oauth-authorization-server/TENANT/one", wantCode: http.StatusNotFound},
		"non-GET":                            {issuer: "https://wicket.test", method: http.MethodPost, path: "/.well-known/oauth-authorization-server", wantCode: http.StatusMethodNotAllowed},
		"non-GET with issuer path":           {issuer: "https://wicket.test/tenant", method: http.MethodPost, path: "/.well-known/oauth-authorization-server/tenant", wantCode: http.StatusMethodNotAllowed},
		"disabled":                           {issuer: "https://wicket.test", options: disabled, method: http.MethodGet, path: "/.well-known/oauth-authorization-server", wantCode: http.StatusNotFound},
		"disabled non-GET":                   {issuer: "https://wicket.test", options: disabled, method: http.MethodPost, path: "/.well-known/oauth-authorization-server", wantCode: http.StatusMethodNotAllowed},
		"disabled with issuer path":          {issuer: "https://wicket.test/tenant", options: disabled, method: http.MethodGet, path: "/.well-known/oauth-authorization-server/tenant", wantCode: http.StatusNotFound},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			options := tc.options
			if options == nil {
				options = config_options.NewWicketOptions()
			}
			handler := NewAuthorizationServerMetadataHandler(newTestDiscoveryHandler(&fakeDiscoveryResponseGenerator{}, tc.issuer, options))
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(tc.method, "https://wicket.test"+tc.path, nil)
			if err := handler.Process(recorder, request); err != nil {
				t.Fatalf("Process: %v", err)
			}
			if recorder.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.wantCode)
			}
			if tc.wantCode != http.StatusOK {
				return
			}
			var document map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
				t.Fatalf("unmarshal document: %v", err)
			}
			if document["issuer"] != tc.issuer {
				t.Fatalf("issuer = %v, want %s", document["issuer"], tc.issuer)
			}
		})
	}
}

func TestAuthorizationServerMetadataHandlerErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		generator *fakeDiscoveryResponseGenerator
		issuer    string
	}{
		"generator fails":     {generator: &fakeDiscoveryResponseGenerator{err: errors.New("boom")}, issuer: "https://wicket.test"},
		"issuer unparsable":   {generator: &fakeDiscoveryResponseGenerator{}, issuer: "https://wicket.test/%zz"},
		"issuer not a string": {generator: &fakeDiscoveryResponseGenerator{document: map[string]any{"issuer": 42}}, issuer: "https://wicket.test"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := NewAuthorizationServerMetadataHandler(newTestDiscoveryHandler(tc.generator, tc.issuer, config_options.NewWicketOptions()))
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "https://wicket.test/.well-known/oauth-authorization-server", nil)
			if err := handler.Process(recorder, request); err == nil {
				t.Fatalf("Process succeeded with status %d, want an error", recorder.Code)
			}
		})
	}
}

func TestAuthorizationServerMetadataMatchesTheDiscoveryDocument(t *testing.T) {
	t.Parallel()

	generator := &fakeDiscoveryResponseGenerator{document: map[string]any{
		"authorization_endpoint": "https://wicket.test/connect/authorize",
		"scopes_supported":       []any{"openid", "api"},
	}}
	options := config_options.NewWicketOptions()
	cacheInterval := 120
	options.Discovery.ResponseCacheInterval = &cacheInterval
	discovery := newTestDiscoveryHandler(generator, "https://wicket.test", options)
	metadata := NewAuthorizationServerMetadataHandler(discovery)

	discoveryRecorder := httptest.NewRecorder()
	if err := discovery.Process(discoveryRecorder, httptest.NewRequest(http.MethodGet, "https://wicket.test/.well-known/openid-configuration", nil)); err != nil {
		t.Fatalf("discovery Process: %v", err)
	}
	metadataRecorder := httptest.NewRecorder()
	if err := metadata.Process(metadataRecorder, httptest.NewRequest(http.MethodGet, "https://wicket.test/.well-known/oauth-authorization-server", nil)); err != nil {
		t.Fatalf("metadata Process: %v", err)
	}
	if discoveryRecorder.Code != http.StatusOK || metadataRecorder.Code != http.StatusOK {
		t.Fatalf("status = %d / %d, want 200", discoveryRecorder.Code, metadataRecorder.Code)
	}
	for _, header := range []string{"Content-Type", "Cache-Control"} {
		if got, want := metadataRecorder.Header().Get(header), discoveryRecorder.Header().Get(header); got != want || want == "" {
			t.Fatalf("%s = %q, want %q (non-empty, as the discovery document)", header, got, want)
		}
	}
	if discoveryRecorder.Body.String() != metadataRecorder.Body.String() {
		t.Fatalf("bodies differ:\ndiscovery: %s\nmetadata:  %s", discoveryRecorder.Body.String(), metadataRecorder.Body.String())
	}
}
