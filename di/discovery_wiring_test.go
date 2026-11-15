// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/tokens"
	"github.com/gonewx/wicket/validators"
)

const wiringBaseUrl = "https://wicket.test"

// mapProvider resolves services from fixed maps; it backs a factory call
// without building the whole container.
type mapProvider struct {
	services map[reflect.Type]any
	lists    map[reflect.Type][]any
}

func (p *mapProvider) GetService(t reflect.Type) any { return p.services[t] }
func (p *mapProvider) IsService(t reflect.Type) bool { _, ok := p.services[t]; return ok }
func (p *mapProvider) IsKeyedService(t reflect.Type, key any) bool {
	return key == nil && p.IsService(t)
}
func (p *mapProvider) GetKeyedService(t reflect.Type, key any) any {
	if key != nil {
		return nil
	}
	return p.services[t]
}
func (p *mapProvider) GetKeyedServices(t reflect.Type, key any) []any {
	if key != nil {
		return nil
	}
	return p.lists[t]
}
func (p *mapProvider) CreateScope() godi.Scope { return nil }
func (p *mapProvider) Close() error            { return nil }

func provide[T any](p *mapProvider, value T) {
	p.services[reflect.TypeFor[T]()] = value
}

type wiringGenerator struct{ document map[string]any }

func (g wiringGenerator) CreateDiscoveryDocument(context.Context, string, string) (map[string]any, error) {
	return g.document, nil
}

func (g wiringGenerator) CreateJwkDocument(context.Context) ([]*models.JsonWebKey, error) {
	return nil, nil
}

type wiringServerUrls struct{}

func (wiringServerUrls) Origin() string                         { return wiringBaseUrl }
func (wiringServerUrls) BasePath() string                       { return "" }
func (wiringServerUrls) BaseUrl() string                        { return wiringBaseUrl + "/" }
func (wiringServerUrls) GetWicketRelativeUrl(rel string) string { return wiringBaseUrl + "/" + rel }

type wiringIssuer struct{}

func (wiringIssuer) GetCurrent() string { return wiringBaseUrl }

// wiringKeys lists fixed signing credentials.
type wiringKeys struct{ credentials []*tokens.SigningCredentials }

func (k wiringKeys) GetSigningCredentials(context.Context, []string) (*tokens.SigningCredentials, error) {
	if len(k.credentials) == 0 {
		return nil, nil
	}
	return k.credentials[0], nil
}

func (k wiringKeys) GetAllSigningCredentials(context.Context) ([]*tokens.SigningCredentials, error) {
	return k.credentials, nil
}

func (wiringKeys) GetValidationKeys(context.Context) ([]*models.SecurityKeyInfo, error) {
	return nil, nil
}

type deliveringBackChannelLogout struct{}

func (deliveringBackChannelLogout) SendLogoutNotificationsAsync(*contexts.LogoutNotificationContext) error {
	return nil
}

func (deliveringBackChannelLogout) DeliversBackChannelLogout() bool { return true }

type tlsSecretParsers struct{}

func (tlsSecretParsers) Parse(*http.Request) (*models.ParsedSecret, error) { return nil, nil }

func (tlsSecretParsers) GetAvailableAuthenticationMethods() []string {
	return []string{wicket.EndpointAuthenticationMethodsTlsClientAuth}
}

// TestDiscoveryHandlerFactoryPassesTheAssemblyFacts checks that the
// composition root factory hands the resolved routes, back-channel logout
// service and secret parsers to the discovery handler: each of them restores
// an entry the filter would otherwise withdraw.
func TestDiscoveryHandlerFactoryPassesTheAssemblyFacts(t *testing.T) {
	t.Parallel()

	options := config_options.NewWicketOptions()
	options.MutualTls.Enabled = true
	provider := &mapProvider{
		services: map[reflect.Type]any{},
		lists: map[reflect.Type][]any{
			reflect.TypeFor[*hosting.Endpoint](): {
				&hosting.Endpoint{Name: wicket.EndpointNamesToken, Path: "/" + wicket.ProtocolRoutePathsToken},
			},
		},
	}
	provide[responses.DiscoveryResponseGenerator](provider, wiringGenerator{document: map[string]any{
		wicket.DiscoveryTokenEndpoint:                         wiringBaseUrl + "/" + wicket.ProtocolRoutePathsToken,
		wicket.DiscoveryBackchannelLogoutSupported:            true,
		wicket.DiscoveryBackchannelLogoutSessionSupported:     true,
		wicket.DiscoveryTlsClientCertificateBoundAccessTokens: true,
		wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported: []string{
			wicket.EndpointAuthenticationMethodsTlsClientAuth,
		},
	}})
	provide[services.ServerUrls](provider, wiringServerUrls{})
	provide[services.IssuerNameService](provider, wiringIssuer{})
	provide(provider, options)
	provide[services.BackchannelLogoutService](provider, deliveringBackChannelLogout{})
	provide[validators.SecretsListParser](provider, tlsSecretParsers{})
	provide[services.KeyMaterialService](provider, wiringKeys{})
	provide(provider, slog.New(slog.DiscardHandler))

	handler := newDiscoveryHandlerFromProvider(provider)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, wiringBaseUrl+wicket.ProtocolRoutePathsDiscoveryConfiguration, nil)
	if err := handler.Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}

	for _, key := range []string{
		wicket.DiscoveryTokenEndpoint,
		wicket.DiscoveryBackchannelLogoutSupported,
		wicket.DiscoveryBackchannelLogoutSessionSupported,
		wicket.DiscoveryTlsClientCertificateBoundAccessTokens,
	} {
		if _, ok := document[key]; !ok {
			t.Errorf("%s withdrawn, want the factory to supply what serves it", key)
		}
	}
	methods, _ := document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported].([]any)
	if !slices.Contains(methods, any(wicket.EndpointAuthenticationMethodsTlsClientAuth)) {
		t.Errorf("%s = %v, want %s kept", wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported, methods, wicket.EndpointAuthenticationMethodsTlsClientAuth)
	}
}

// TestDiscoveryHandlerFactoryDeclaresSignedIntrospection checks that the
// composition root factory hands the key material to the discovery handler,
// which then advertises the introspection signing algorithms.
func TestDiscoveryHandlerFactoryDeclaresSignedIntrospection(t *testing.T) {
	t.Parallel()

	provider := &mapProvider{
		services: map[reflect.Type]any{},
		lists: map[reflect.Type][]any{
			reflect.TypeFor[*hosting.Endpoint](): {
				&hosting.Endpoint{Name: wicket.EndpointNamesIntrospection, Path: "/" + wicket.ProtocolRoutePathsIntrospection},
			},
		},
	}
	provide[responses.DiscoveryResponseGenerator](provider, wiringGenerator{document: map[string]any{
		wicket.DiscoveryIntrospectionEndpoint: wiringBaseUrl + "/" + wicket.ProtocolRoutePathsIntrospection,
	}})
	provide[services.ServerUrls](provider, wiringServerUrls{})
	provide[services.IssuerNameService](provider, wiringIssuer{})
	provide(provider, config_options.NewWicketOptions())
	provide[services.BackchannelLogoutService](provider, deliveringBackChannelLogout{})
	provide[validators.SecretsListParser](provider, tlsSecretParsers{})
	provide[services.KeyMaterialService](provider, wiringKeys{credentials: []*tokens.SigningCredentials{{Algorithm: "PS256"}, {Algorithm: "ES256"}, {Algorithm: "PS256"}}})
	provide(provider, slog.New(slog.DiscardHandler))

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, wiringBaseUrl+wicket.ProtocolRoutePathsDiscoveryConfiguration, nil)
	if err := newDiscoveryHandlerFromProvider(provider).Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	got := document[wicket.DiscoveryIntrospectionSigningAlgValuesSupported]
	if !reflect.DeepEqual(got, []any{"PS256", "ES256"}) {
		t.Fatalf("%s = %v, want [PS256 ES256]", wicket.DiscoveryIntrospectionSigningAlgValuesSupported, got)
	}
}
