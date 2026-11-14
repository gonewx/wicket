// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
)

var tlsMethods = []string{
	wicket.EndpointAuthenticationMethodsTlsClientAuth,
	wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
}

func mutualTlsHandler(t *testing.T, mutualTls bool, parserMethods []string, serve bool) (map[string]any, string) {
	t.Helper()
	options := config_options.NewWicketOptions()
	options.MutualTls.Enabled = mutualTls
	logs := &bytes.Buffer{}
	paths := append(slices.Clone(registeredEndpointPaths),
		"/"+wicket.ProtocolRoutePathsRevocation,
		"/"+wicket.ProtocolRoutePathsDeviceAuthorization,
		"/"+wicket.ProtocolRoutePathsMtlsToken,
		"/"+wicket.ProtocolRoutePathsMtlsRevocation,
		"/"+wicket.ProtocolRoutePathsMtlsIntrospection,
		"/"+wicket.ProtocolRoutePathsMtlsDeviceAuthorization,
	)
	document := generatedDocument(mutualTls)
	if !mutualTls {
		// Without MutualTls the generator lists the parser methods only.
		document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported] = slices.Clone(parserMethods)
	} else {
		document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported] = append(slices.Clone(parserMethods), tlsMethods...)
	}
	handler := NewDiscoveryHandler(
		&fakeDiscoveryResponseGenerator{document: document},
		&fakeServerUrls{base: advertisementBaseUrl},
		&fakeIssuerNameService{issuer: advertisementBaseUrl},
		options,
		paths,
		markedBackChannelLogout{delivers: true},
		fakeSecretsListParser{methods: parserMethods},
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
	if serve {
		handler.ServeClientCertificateAuthentication()
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, advertisementBaseUrl+wicket.ProtocolRoutePathsDiscoveryConfiguration, nil)
	if err := handler.Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	return decoded, logs.String()
}

func methodsOf(document map[string]any) []string {
	values, _ := document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported].([]any)
	methods := make([]string, 0, len(values))
	for _, value := range values {
		method, _ := value.(string)
		methods = append(methods, method)
	}
	return methods
}

var bothParsers = []string{
	wicket.EndpointAuthenticationMethodsBasicAuthentication,
	wicket.EndpointAuthenticationMethodsPostBody,
	wicket.EndpointAuthenticationMethodsTlsClientAuth,
	wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
}

func TestServedMutualTlsIsAdvertisedOnceWithoutBoundTokens(t *testing.T) {
	t.Parallel()

	document, logs := mutualTlsHandler(t, true, bothParsers, true)
	want := bothParsers
	if got := methodsOf(document); !slices.Equal(got, want) {
		t.Fatalf("methods = %v, want %v", got, want)
	}
	if _, ok := document[wicket.DiscoveryTlsClientCertificateBoundAccessTokens]; ok {
		t.Fatalf("%s advertised before bound tokens exist", wicket.DiscoveryTlsClientCertificateBoundAccessTokens)
	}
	aliases, _ := document[wicket.DiscoveryMtlsEndpointAliases].(map[string]any)
	if len(aliases) != 4 {
		t.Fatalf("aliases = %v, want the four served aliases", aliases)
	}
	if strings.Contains(logs, "Mutual TLS") {
		t.Fatalf("unexpected mutual TLS warning: %s", logs)
	}
}

func TestServedMutualTlsIsNotAdvertisedWhileMutualTlsIsOff(t *testing.T) {
	t.Parallel()

	document, logs := mutualTlsHandler(t, false, bothParsers, true)
	want := []string{wicket.EndpointAuthenticationMethodsBasicAuthentication, wicket.EndpointAuthenticationMethodsPostBody}
	if got := methodsOf(document); !slices.Equal(got, want) {
		t.Fatalf("methods = %v, want %v", got, want)
	}
	for _, key := range []string{wicket.DiscoveryTlsClientCertificateBoundAccessTokens, wicket.DiscoveryMtlsEndpointAliases} {
		if _, ok := document[key]; ok {
			t.Fatalf("%s advertised while MutualTls is off", key)
		}
	}
	if strings.Contains(logs, "level=WARN") {
		t.Fatalf("unexpected warning: %s", logs)
	}
}

func TestOnlySelfSignedServedWithdrawsPkiAsBefore(t *testing.T) {
	t.Parallel()

	parsers := []string{
		wicket.EndpointAuthenticationMethodsBasicAuthentication,
		wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
	}
	document, logs := mutualTlsHandler(t, true, parsers, true)
	if got := methodsOf(document); !slices.Equal(got, parsers) {
		t.Fatalf("methods = %v, want %v", got, parsers)
	}
	if !strings.Contains(logs, "Mutual TLS is enabled") {
		t.Fatalf("withdrawn tls_client_auth was not warned about: %s", logs)
	}
}

func TestUnservedHandlerKeepsTheBaselineDocument(t *testing.T) {
	t.Parallel()

	document, _ := mutualTlsHandler(t, true, bothParsers, false)
	if value, ok := document[wicket.DiscoveryTlsClientCertificateBoundAccessTokens]; !ok || value != true {
		t.Fatalf("%s = %v, want the baseline true", wicket.DiscoveryTlsClientCertificateBoundAccessTokens, value)
	}
	want := append(slices.Clone(bothParsers), tlsMethods...)
	if got := methodsOf(document); !slices.Equal(got, want) {
		t.Fatalf("methods = %v, want the baseline %v", got, want)
	}
}

func TestSettleMutualTlsAdvertisementKeepsListTypes(t *testing.T) {
	t.Parallel()

	options := config_options.NewWicketOptions()
	options.MutualTls.Enabled = true
	document := map[string]any{
		wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported: []string{"a", "tls_client_auth", "a", "tls_client_auth"},
	}
	settleMutualTlsAdvertisement(document, options)
	if got, ok := document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported].([]string); !ok || !slices.Equal(got, []string{"a", "tls_client_auth"}) {
		t.Fatalf("[]string list = %#v", document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
	}

	options.MutualTls.Enabled = false
	document = map[string]any{
		wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported: []any{"a", "self_signed_tls_client_auth", "b", "a", 7},
	}
	settleMutualTlsAdvertisement(document, options)
	got, ok := document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported].([]any)
	if !ok || !slices.Equal(got, []any{"a", "b", 7}) {
		t.Fatalf("[]any list = %#v", document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
	}
}
