// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
)

func TestDiscoveryRequestObjectSigningAlgorithms(t *testing.T) {
	key := wicket.DiscoveryRequestObjectSigningAlgorithmsSupported
	generatedTwelve := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512"}
	asymmetricNine := []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

	cases := []struct {
		name       string
		asymmetric bool
		generated  any
		custom     bool
		want       []string
	}{
		{name: "off keeps the generated list", generated: generatedTwelve, want: generatedTwelve},
		{name: "off keeps a host list", generated: []string{"HS256", "ES256"}, custom: true, want: []string{"HS256", "ES256"}},
		{name: "on keeps the asymmetric algorithms", asymmetric: true, generated: generatedTwelve, want: asymmetricNine},
		{name: "on filters a list decoded from JSON", asymmetric: true, generated: []any{"HS256", "ES256", 7, "none"}, want: []string{"ES256"}},
		{name: "on filters a host list", asymmetric: true, generated: []string{"HS512", "PS384", "EdDSA"}, custom: true, want: []string{"PS384"}},
		{name: "on removes a list left empty", asymmetric: true, generated: []string{"HS256", "none"}, want: nil},
		{name: "on removes a host list left empty", asymmetric: true, generated: []any{"HS256"}, custom: true, want: nil},
		{name: "on removes a value that is not a list", asymmetric: true, generated: "HS256", custom: true, want: nil},
		{name: "on without the key", asymmetric: true, generated: nil, want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := config_options.NewWicketOptions()
			generated := map[string]any{wicket.DiscoveryIssuer: advertisementBaseUrl}
			if tc.generated != nil {
				generated[key] = tc.generated
				if tc.custom {
					options.Discovery.CustomEntries = map[string]any{key: tc.generated}
				}
			}
			handler := NewDiscoveryHandler(
				&fakeDiscoveryResponseGenerator{document: generated},
				&fakeServerUrls{base: advertisementBaseUrl},
				&fakeIssuerNameService{issuer: advertisementBaseUrl},
				options,
				registeredEndpointPaths,
				noOpBackChannelLogout{},
				fakeSecretsListParser{},
				quietLogger(),
			)
			if tc.asymmetric {
				handler.ServeAsymmetricRequestObjectsOnly()
			}

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, advertisementBaseUrl+wicket.ProtocolRoutePathsDiscoveryConfiguration, nil)
			if err := handler.Process(recorder, request); err != nil {
				t.Fatalf("Process: %v", err)
			}
			var document map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
				t.Fatalf("unmarshal document: %v", err)
			}
			raw, present := document[key]
			if present != (tc.want != nil) {
				t.Fatalf("%s present = %v (%v), want %v", key, present, raw, tc.want != nil)
			}
			if !present {
				return
			}
			if got := stringList(t, raw); !slices.Equal(got, tc.want) {
				t.Fatalf("%s = %v, want %v", key, got, tc.want)
			}
		})
	}
}
