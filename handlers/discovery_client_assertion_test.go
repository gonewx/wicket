// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	config_options "github.com/gonewx/wicket/config/options"
)

const algorithmsKey = "token_endpoint_auth_signing_alg_values_supported"

func TestHandlerWrittenDiscoveryKeys(t *testing.T) {
	if len(handlerWrittenDiscoveryKeys) != 4 {
		t.Fatalf("handler written keys: %v", handlerWrittenDiscoveryKeys)
	}
	for _, key := range []string{algorithmsKey, wicket.DiscoveryPushedAuthorizationRequestEndpoint, wicket.DiscoveryRequirePushedAuthorizationRequests, wicket.DiscoveryDPoPSigningAlgValuesSupported} {
		if _, ok := handlerWrittenDiscoveryKeys[key]; !ok {
			t.Fatalf("%s is not a handler written key", key)
		}
	}
	if wicket.DiscoveryTokenEndpointAuthSigningAlgorithmsSupported != algorithmsKey {
		t.Fatalf("constant value changed: %q", wicket.DiscoveryTokenEndpointAuthSigningAlgorithmsSupported)
	}
	for key := range handlerWrittenDiscoveryKeys {
		if _, generated := generatedDiscoveryKeys[key]; generated {
			t.Fatalf("%s is in both key sets", key)
		}
	}
	source, err := os.ReadFile("../responses/impl/discovery_response_generator.go")
	if err != nil {
		t.Fatalf("read generator source: %v", err)
	}
	if strings.Contains(string(source), "DiscoveryTokenEndpointAuthSigningAlgorithmsSupported") {
		t.Fatalf("the generator writes %s; it must stay a handler written key only", algorithmsKey)
	}
}

func TestIsHostEntryKeepsCustomKeysOutsideBothSets(t *testing.T) {
	options := config_options.NewWicketOptions()
	options.Discovery.CustomEntries = map[string]any{
		"registration_endpoint":         "https://host.example/register",
		algorithmsKey:                   []string{"HS256"},
		wicket.DiscoveryScopesSupported: []string{"x"},
		"service_documentation":         "https://host.example/docs",
	}
	filter := &discoveryFilter{document: map[string]any{}, options: options}
	for key, want := range map[string]bool{
		"registration_endpoint":         true,
		"service_documentation":         true,
		algorithmsKey:                   false,
		wicket.DiscoveryScopesSupported: false,
		"not_a_custom_entry":            false,
	} {
		if got := filter.isHostEntry(key); got != want {
			t.Errorf("isHostEntry(%s) = %v, want %v", key, got, want)
		}
	}
}

// assertAlgorithmsGuard is the structural guard of the algorithms key: it is
// advertised only next to private_key_jwt and only with supported values.
func assertAlgorithmsGuard(t *testing.T, document map[string]any) {
	t.Helper()
	raw, present := document[algorithmsKey]
	if !present {
		return
	}
	methods := stringList(t, document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
	if !slices.Contains(methods, "private_key_jwt") {
		t.Fatalf("%s advertised without private_key_jwt among %v", algorithmsKey, methods)
	}
	algorithms := stringList(t, raw)
	if len(algorithms) == 0 {
		t.Fatalf("%s advertised empty", algorithmsKey)
	}
	for _, algorithm := range algorithms {
		if algorithm == "none" || !slices.Contains(clientassertion.SupportedSigningAlgorithms(), algorithm) {
			t.Fatalf("%s advertises %q", algorithmsKey, algorithm)
		}
	}
}

func stringList(t *testing.T, value any) []string {
	t.Helper()
	switch values := value.(type) {
	case nil:
		return nil
	case []string:
		return values
	case []any:
		out := make([]string, 0, len(values))
		for _, item := range values {
			text, ok := item.(string)
			if !ok {
				t.Fatalf("non string list item %v", item)
			}
			out = append(out, text)
		}
		return out
	}
	t.Fatalf("not a list: %T", value)
	return nil
}

func TestDiscoveryClientAssertionSigningAlgorithms(t *testing.T) {
	basic := wicket.EndpointAuthenticationMethodsBasicAuthentication
	post := wicket.EndpointAuthenticationMethodsPostBody
	assertion := wicket.EndpointAuthenticationMethodsPrivateKeyJwt

	cases := []struct {
		name         string
		algorithms   []string
		setAlgorithm bool
		registered   []string
		generated    any
		custom       any
		want         []string
		wantWarnings int
	}{
		{name: "nothing registered and nothing set", registered: []string{basic, post}, generated: []string{basic, post}},
		{name: "custom entry without the parser", registered: []string{basic, post}, generated: []string{basic, post},
			custom: []string{"HS256"}, wantWarnings: 1},
		{name: "parser registered", setAlgorithm: true, algorithms: []string{"PS256", "ES256"},
			registered: []string{basic, post, assertion}, generated: []string{basic, post, assertion}, want: []string{"PS256", "ES256"}},
		{name: "parser registered, document decoded from JSON", setAlgorithm: true, algorithms: []string{"PS256", "ES256"},
			registered: []string{basic, post, assertion}, generated: []any{basic, post, assertion}, want: []string{"PS256", "ES256"}},
		{name: "parser registered and custom entry", setAlgorithm: true, algorithms: []string{"PS256", "ES256"},
			registered: []string{basic, post, assertion}, generated: []string{basic, post, assertion},
			custom: []string{"none"}, want: []string{"PS256", "ES256"}, wantWarnings: 1},
		{name: "methods not shown", setAlgorithm: true, algorithms: []string{"PS256", "ES256"},
			registered: []string{basic, post, assertion}, generated: nil},
		{name: "methods not shown and custom entry", setAlgorithm: true, algorithms: []string{"PS256", "ES256"},
			registered: []string{basic, post, assertion}, generated: nil, custom: []string{"RS256"}, wantWarnings: 1},
		{name: "method missing from the document", setAlgorithm: true, algorithms: []string{"PS256"},
			registered: []string{basic, post, assertion}, generated: []string{basic, post}},
		{name: "method only in the document", setAlgorithm: true, algorithms: []string{"PS256"},
			registered: []string{basic, post}, generated: []string{basic, post, assertion}},
		{name: "parser names no algorithm", setAlgorithm: true, algorithms: nil,
			registered: []string{basic, post, assertion}, generated: []string{basic, post, assertion}, wantWarnings: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := config_options.NewWicketOptions()
			generated := map[string]any{
				wicket.DiscoveryIssuer:        advertisementBaseUrl,
				wicket.DiscoveryTokenEndpoint: advertisementBaseUrl + "/connect/token",
			}
			if tc.generated != nil {
				generated[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported] = tc.generated
			} else {
				options.Discovery.ShowTokenEndpointAuthenticationMethods = false
			}
			if tc.custom != nil {
				options.Discovery.CustomEntries = map[string]any{algorithmsKey: tc.custom}
				generated[algorithmsKey] = tc.custom
			}
			logs := &bytes.Buffer{}
			handler := NewDiscoveryHandler(
				&fakeDiscoveryResponseGenerator{document: generated},
				&fakeServerUrls{base: advertisementBaseUrl},
				&fakeIssuerNameService{issuer: advertisementBaseUrl},
				options,
				registeredEndpointPaths,
				noOpBackChannelLogout{},
				fakeSecretsListParser{methods: tc.registered},
				slog.New(slog.NewTextHandler(logs, nil)),
			)
			if tc.setAlgorithm {
				source := slices.Clone(tc.algorithms)
				handler.SetClientAssertionSigningAlgorithms(source)
				if len(source) > 0 {
					source[0] = "none"
				}
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
			assertAlgorithmsGuard(t, document)
			got := stringList(t, document[algorithmsKey])
			if !slices.Equal(got, tc.want) {
				t.Fatalf("%s = %v, want %v", algorithmsKey, got, tc.want)
			}
			if _, present := document[algorithmsKey]; present != (tc.want != nil) {
				t.Fatalf("%s present = %v", algorithmsKey, present)
			}
			if warnings := strings.Count(logs.String(), "level=WARN"); warnings != tc.wantWarnings {
				t.Fatalf("warnings = %d, want %d: %s", warnings, tc.wantWarnings, logs.String())
			}
			if tc.custom != nil && !strings.Contains(logs.String(), "A custom discovery entry named token_endpoint_auth_signing_alg_values_supported is ignored; the key is written only from the registered client assertion parser.") {
				t.Fatalf("missing the custom entry warning: %s", logs.String())
			}
			for _, value := range []string{"HS256", "none"} {
				if strings.Contains(logs.String(), value) {
					t.Fatalf("log carries the host value %q: %s", value, logs.String())
				}
			}
		})
	}
}
