// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/models/contexts"
)

const advertisementBaseUrl = "https://wicket.test"

// registeredEndpointPaths mirrors the default endpoint registrations.
var registeredEndpointPaths = []string{
	"/" + wicket.ProtocolRoutePathsAuthorize,
	"/" + wicket.ProtocolRoutePathsAuthorizeCallback,
	"/" + wicket.ProtocolRoutePathsToken,
	wicket.ProtocolRoutePathsDiscoveryConfiguration,
	wicket.ProtocolRoutePathsDiscoveryWebKeys,
	"/" + wicket.ProtocolRoutePathsCheckSession,
	"/" + wicket.ProtocolRoutePathsBackchannelAuthentication,
	"/" + wicket.ProtocolRoutePathsIntrospection,
	"/" + wicket.ProtocolRoutePathsUserInfo,
	"/" + wicket.ProtocolRoutePathsEndSession,
	"/" + wicket.ProtocolRoutePathsEndSessionCallback,
}

func advertisementUrl(path string) string {
	return advertisementBaseUrl + "/" + strings.TrimLeft(path, "/")
}

// generatedDocument mirrors the entries the generator emits for default
// endpoint options, optionally with the mutual TLS additions.
func generatedDocument(mutualTls bool) map[string]any {
	document := map[string]any{
		wicket.DiscoveryIssuer:                             advertisementBaseUrl,
		wicket.DiscoveryJwksUri:                            advertisementUrl(wicket.ProtocolRoutePathsDiscoveryWebKeys),
		wicket.DiscoveryAuthorizationEndpoint:              advertisementUrl(wicket.ProtocolRoutePathsAuthorize),
		wicket.DiscoveryTokenEndpoint:                      advertisementUrl(wicket.ProtocolRoutePathsToken),
		wicket.DiscoveryUserInfoEndpoint:                   advertisementUrl(wicket.ProtocolRoutePathsUserInfo),
		wicket.DiscoveryEndSessionEndpoint:                 advertisementUrl(wicket.ProtocolRoutePathsEndSession),
		wicket.DiscoveryCheckSessionIframe:                 advertisementUrl(wicket.ProtocolRoutePathsCheckSession),
		wicket.DiscoveryRevocationEndpoint:                 advertisementUrl(wicket.ProtocolRoutePathsRevocation),
		wicket.DiscoveryIntrospectionEndpoint:              advertisementUrl(wicket.ProtocolRoutePathsIntrospection),
		wicket.DiscoveryDeviceAuthorizationEndpoint:        advertisementUrl(wicket.ProtocolRoutePathsDeviceAuthorization),
		wicket.DiscoveryBackchannelAuthenticationEndpoint:  advertisementUrl(wicket.ProtocolRoutePathsBackchannelAuthentication),
		wicket.DiscoveryFrontChannelLogoutSupported:        true,
		wicket.DiscoveryFrontChannelLogoutSessionSupported: true,
		wicket.DiscoveryBackchannelLogoutSupported:         true,
		wicket.DiscoveryBackchannelLogoutSessionSupported:  true,
		wicket.DiscoveryGrantTypesSupported: []string{
			wicket.GrantTypeAuthorizationCode,
			wicket.GrantTypeClientCredentials,
			wicket.GrantTypeRefreshToken,
			wicket.GrantTypeImplicit,
			wicket.GrantTypeDeviceCode,
			wicket.GrantTypeBackchannelAuthentication,
		},
		wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported: []string{
			wicket.EndpointAuthenticationMethodsBasicAuthentication,
			wicket.EndpointAuthenticationMethodsPostBody,
		},
		wicket.DiscoveryAuthorizationResponseIssParameterSupported: true,
	}
	if mutualTls {
		document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported] = append(
			document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported].([]string),
			wicket.EndpointAuthenticationMethodsTlsClientAuth,
			wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
		)
		document[wicket.DiscoveryTlsClientCertificateBoundAccessTokens] = true
		document[wicket.DiscoveryMtlsEndpointAliases] = map[string]string{
			wicket.DiscoveryTokenEndpoint:               advertisementUrl(wicket.ProtocolRoutePathsMtlsToken),
			wicket.DiscoveryRevocationEndpoint:          advertisementUrl(wicket.ProtocolRoutePathsMtlsRevocation),
			wicket.DiscoveryIntrospectionEndpoint:       advertisementUrl(wicket.ProtocolRoutePathsMtlsIntrospection),
			wicket.DiscoveryDeviceAuthorizationEndpoint: advertisementUrl(wicket.ProtocolRoutePathsMtlsDeviceAuthorization),
		}
	}
	return document
}

type noOpBackChannelLogout struct{}

func (noOpBackChannelLogout) SendLogoutNotificationsAsync(*contexts.LogoutNotificationContext) error {
	return nil
}

type markedBackChannelLogout struct {
	noOpBackChannelLogout
	delivers bool
}

func (s markedBackChannelLogout) DeliversBackChannelLogout() bool { return s.delivers }

func newRecordingLogger() (*slog.Logger, *bytes.Buffer) {
	buffer := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buffer, &slog.HandlerOptions{Level: slog.LevelDebug})), buffer
}

func TestFilterDiscoveryAdvertisement(t *testing.T) {
	t.Parallel()

	defaultAssembly := func() discoveryAssembly {
		return discoveryAssembly{
			endpointPaths:     slices.Clone(registeredEndpointPaths),
			backChannelLogout: noOpBackChannelLogout{},
			authenticationMethods: []string{
				wicket.EndpointAuthenticationMethodsBasicAuthentication,
				wicket.EndpointAuthenticationMethodsPostBody,
			},
		}
	}

	tests := []struct {
		name         string
		mutualTls    bool
		configure    func(*config_options.WicketOptions)
		assembly     func(discoveryAssembly) discoveryAssembly
		edit         func(map[string]any)
		present      []string
		absent       []string
		values       map[string]any
		grantTypes   []string
		authMethods  []string
		wantWarnings int
	}{
		{
			name: "default assembly withdraws unservable entries",
			present: []string{
				wicket.DiscoveryJwksUri,
				wicket.DiscoveryAuthorizationEndpoint,
				wicket.DiscoveryTokenEndpoint,
				wicket.DiscoveryUserInfoEndpoint,
				wicket.DiscoveryEndSessionEndpoint,
				wicket.DiscoveryCheckSessionIframe,
				wicket.DiscoveryIntrospectionEndpoint,
				wicket.DiscoveryBackchannelAuthenticationEndpoint,
				wicket.DiscoveryFrontChannelLogoutSupported,
				wicket.DiscoveryFrontChannelLogoutSessionSupported,
				wicket.DiscoveryAuthorizationResponseIssParameterSupported,
			},
			absent: []string{
				wicket.DiscoveryRevocationEndpoint,
				wicket.DiscoveryDeviceAuthorizationEndpoint,
				wicket.DiscoveryBackchannelLogoutSupported,
				wicket.DiscoveryBackchannelLogoutSessionSupported,
			},
			grantTypes: []string{
				wicket.GrantTypeAuthorizationCode,
				wicket.GrantTypeClientCredentials,
				wicket.GrantTypeRefreshToken,
				wicket.GrantTypeImplicit,
				wicket.GrantTypeBackchannelAuthentication,
			},
			authMethods: []string{
				wicket.EndpointAuthenticationMethodsBasicAuthentication,
				wicket.EndpointAuthenticationMethodsPostBody,
			},
		},
		{
			name:      "iss parameter switch off",
			configure: func(o *config_options.WicketOptions) { o.EmitIssuerIdentificationResponseParameter = false },
			absent:    []string{wicket.DiscoveryAuthorizationResponseIssParameterSupported},
		},
		{
			name:      "mutual TLS enabled without a tls parser",
			mutualTls: true,
			configure: func(o *config_options.WicketOptions) { o.MutualTls.Enabled = true },
			absent: []string{
				wicket.DiscoveryTlsClientCertificateBoundAccessTokens,
				wicket.DiscoveryMtlsEndpointAliases,
			},
			authMethods: []string{
				wicket.EndpointAuthenticationMethodsBasicAuthentication,
				wicket.EndpointAuthenticationMethodsPostBody,
			},
			wantWarnings: 1,
		},
		{
			name:      "mutual TLS with only the tls_client_auth parser",
			mutualTls: true,
			configure: func(o *config_options.WicketOptions) { o.MutualTls.Enabled = true },
			assembly: func(a discoveryAssembly) discoveryAssembly {
				a.authenticationMethods = append(a.authenticationMethods, wicket.EndpointAuthenticationMethodsTlsClientAuth)
				return a
			},
			present: []string{wicket.DiscoveryTlsClientCertificateBoundAccessTokens},
			authMethods: []string{
				wicket.EndpointAuthenticationMethodsBasicAuthentication,
				wicket.EndpointAuthenticationMethodsPostBody,
				wicket.EndpointAuthenticationMethodsTlsClientAuth,
			},
			wantWarnings: 1,
		},
		{
			name:      "mutual TLS path aliases pointing at unregistered routes",
			mutualTls: true,
			configure: func(o *config_options.WicketOptions) { o.MutualTls.Enabled = true },
			assembly: func(a discoveryAssembly) discoveryAssembly {
				a.authenticationMethods = append(a.authenticationMethods,
					wicket.EndpointAuthenticationMethodsTlsClientAuth,
					wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
				)
				return a
			},
			edit: func(d map[string]any) {
				aliases := d[wicket.DiscoveryMtlsEndpointAliases].(map[string]string)
				// the generator's path form appends the route without a separator
				aliases[wicket.DiscoveryTokenEndpoint] = advertisementBaseUrl + wicket.ProtocolRoutePathsMtlsToken
			},
			present: []string{wicket.DiscoveryTlsClientCertificateBoundAccessTokens},
			absent:  []string{wicket.DiscoveryMtlsEndpointAliases},
			authMethods: []string{
				wicket.EndpointAuthenticationMethodsBasicAuthentication,
				wicket.EndpointAuthenticationMethodsPostBody,
				wicket.EndpointAuthenticationMethodsTlsClientAuth,
				wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
			},
			wantWarnings: 1,
		},
		{
			name:      "mutual TLS keeps routed aliases of advertised endpoints",
			mutualTls: true,
			assembly: func(a discoveryAssembly) discoveryAssembly {
				a.authenticationMethods = append(a.authenticationMethods, wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth)
				a.endpointPaths = append(a.endpointPaths,
					"/"+wicket.ProtocolRoutePathsMtlsIntrospection,
					"/"+wicket.ProtocolRoutePathsMtlsRevocation,
					"/"+wicket.ProtocolRoutePathsMtlsDeviceAuthorization,
				)
				return a
			},
			edit: func(d map[string]any) {
				aliases := d[wicket.DiscoveryMtlsEndpointAliases].(map[string]string)
				// sub-domain form: another host, judged by its primary endpoint only
				aliases[wicket.DiscoveryTokenEndpoint] = "https://mtls.wicket.test/" + wicket.ProtocolRoutePathsToken
			},
			values: map[string]any{
				wicket.DiscoveryMtlsEndpointAliases: map[string]string{
					wicket.DiscoveryTokenEndpoint:         "https://mtls.wicket.test/" + wicket.ProtocolRoutePathsToken,
					wicket.DiscoveryIntrospectionEndpoint: advertisementUrl(wicket.ProtocolRoutePathsMtlsIntrospection),
				},
			},
			authMethods: []string{
				wicket.EndpointAuthenticationMethodsBasicAuthentication,
				wicket.EndpointAuthenticationMethodsPostBody,
				wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
			},
		},
		{
			name:      "mutual TLS aliases dropped once every primary endpoint is gone",
			mutualTls: true,
			assembly: func(a discoveryAssembly) discoveryAssembly {
				a.endpointPaths = []string{wicket.ProtocolRoutePathsDiscoveryConfiguration}
				a.authenticationMethods = []string{wicket.EndpointAuthenticationMethodsTlsClientAuth}
				return a
			},
			absent: []string{wicket.DiscoveryMtlsEndpointAliases, wicket.DiscoveryTokenEndpoint},
		},
		{
			name: "back-channel logout capability implemented",
			assembly: func(a discoveryAssembly) discoveryAssembly {
				a.backChannelLogout = markedBackChannelLogout{delivers: true}
				return a
			},
			values: map[string]any{
				wicket.DiscoveryBackchannelLogoutSupported:        true,
				wicket.DiscoveryBackchannelLogoutSessionSupported: true,
			},
		},
		{
			name: "back-channel logout capability reporting false",
			assembly: func(a discoveryAssembly) discoveryAssembly {
				a.backChannelLogout = markedBackChannelLogout{delivers: false}
				return a
			},
			absent: []string{
				wicket.DiscoveryBackchannelLogoutSupported,
				wicket.DiscoveryBackchannelLogoutSessionSupported,
			},
		},
		{
			name: "registered revocation and device routes restore their entries",
			assembly: func(a discoveryAssembly) discoveryAssembly {
				a.endpointPaths = append(a.endpointPaths,
					"/"+wicket.ProtocolRoutePathsRevocation,
					"/"+strings.ToUpper(wicket.ProtocolRoutePathsDeviceAuthorization),
				)
				return a
			},
			present: []string{
				wicket.DiscoveryRevocationEndpoint,
				wicket.DiscoveryDeviceAuthorizationEndpoint,
			},
			grantTypes: []string{
				wicket.GrantTypeAuthorizationCode,
				wicket.GrantTypeClientCredentials,
				wicket.GrantTypeRefreshToken,
				wicket.GrantTypeImplicit,
				wicket.GrantTypeDeviceCode,
				wicket.GrantTypeBackchannelAuthentication,
			},
		},
		{
			name: "host custom endpoint pointing at an unregistered path",
			configure: func(o *config_options.WicketOptions) {
				o.Discovery.CustomEntries = map[string]any{
					"foo_endpoint": advertisementBaseUrl + "/foo",
					"bar_endpoint": "~/bar",
				}
			},
			edit: func(d map[string]any) {
				d["foo_endpoint"] = advertisementBaseUrl + "/foo"
				d["bar_endpoint"] = advertisementBaseUrl + "/bar"
			},
			values: map[string]any{
				"foo_endpoint": advertisementBaseUrl + "/foo",
				"bar_endpoint": advertisementBaseUrl + "/bar",
			},
		},
		{
			name: "custom entry sharing a generated key stays filtered",
			configure: func(o *config_options.WicketOptions) {
				o.Discovery.CustomEntries = map[string]any{
					wicket.DiscoveryRevocationEndpoint: "https://elsewhere.test/revoke",
				}
			},
			absent: []string{wicket.DiscoveryRevocationEndpoint},
		},
		{
			name: "custom entries equal to the generated values stay filtered",
			configure: func(o *config_options.WicketOptions) {
				o.Discovery.ExpandRelativePathsInCustomEntries = true
				o.Discovery.CustomEntries = map[string]any{
					wicket.DiscoveryRevocationEndpoint:          advertisementUrl(wicket.ProtocolRoutePathsRevocation),
					wicket.DiscoveryDeviceAuthorizationEndpoint: "~/" + wicket.ProtocolRoutePathsDeviceAuthorization,
					wicket.DiscoveryBackchannelLogoutSupported:  true,
				}
			},
			absent: []string{
				wicket.DiscoveryRevocationEndpoint,
				wicket.DiscoveryDeviceAuthorizationEndpoint,
				wicket.DiscoveryBackchannelLogoutSupported,
			},
		},
		{
			name: "external endpoint URL is kept",
			edit: func(d map[string]any) {
				d[wicket.DiscoveryRegistrationEndpoint] = "https://elsewhere.test/connect/register"
				d["lookalike_endpoint"] = advertisementBaseUrl + ".elsewhere.test/connect/register"
			},
			values: map[string]any{
				wicket.DiscoveryRegistrationEndpoint: "https://elsewhere.test/connect/register",
				"lookalike_endpoint":                 advertisementBaseUrl + ".elsewhere.test/connect/register",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			options := config_options.NewWicketOptions()
			if tt.configure != nil {
				tt.configure(options)
			}
			assembly := defaultAssembly()
			if tt.assembly != nil {
				assembly = tt.assembly(assembly)
			}
			document := generatedDocument(tt.mutualTls)
			if tt.edit != nil {
				tt.edit(document)
			}
			logger, logs := newRecordingLogger()

			filterDiscoveryAdvertisement(document, advertisementBaseUrl+"/", options, assembly, logger)

			for _, key := range tt.present {
				if _, ok := document[key]; !ok {
					t.Errorf("%s missing from filtered document", key)
				}
			}
			for _, key := range tt.absent {
				if value, ok := document[key]; ok {
					t.Errorf("%s = %v, want it withdrawn", key, value)
				}
			}
			for key, want := range tt.values {
				got, ok := document[key]
				if !ok {
					t.Errorf("%s missing, want %v", key, want)
					continue
				}
				if !equalJson(t, got, want) {
					t.Errorf("%s = %v, want %v", key, got, want)
				}
			}
			if tt.grantTypes != nil {
				if got := document[wicket.DiscoveryGrantTypesSupported]; !equalJson(t, got, tt.grantTypes) {
					t.Errorf("grant types = %v, want %v", got, tt.grantTypes)
				}
			}
			if tt.authMethods != nil {
				if got := document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported]; !equalJson(t, got, tt.authMethods) {
					t.Errorf("auth methods = %v, want %v", got, tt.authMethods)
				}
			}
			if got := strings.Count(logs.String(), "level=WARN"); got != tt.wantWarnings {
				t.Errorf("warnings = %d, want %d: %s", got, tt.wantWarnings, logs.String())
			}
		})
	}
}

func TestFilterDiscoveryAdvertisementLeavesSourceListsIntact(t *testing.T) {
	t.Parallel()

	grantTypes := []string{wicket.GrantTypeAuthorizationCode, wicket.GrantTypeDeviceCode, wicket.GrantTypeRefreshToken}
	methods := []string{wicket.EndpointAuthenticationMethodsTlsClientAuth, wicket.EndpointAuthenticationMethodsPostBody}
	document := map[string]any{
		wicket.DiscoveryGrantTypesSupported:                         grantTypes,
		wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported: methods,
	}

	filterDiscoveryAdvertisement(document, advertisementBaseUrl, config_options.NewWicketOptions(), discoveryAssembly{}, quietLogger())

	if !slices.Equal(grantTypes, []string{wicket.GrantTypeAuthorizationCode, wicket.GrantTypeDeviceCode, wicket.GrantTypeRefreshToken}) {
		t.Fatalf("source grant types mutated: %v", grantTypes)
	}
	if !slices.Equal(methods, []string{wicket.EndpointAuthenticationMethodsTlsClientAuth, wicket.EndpointAuthenticationMethodsPostBody}) {
		t.Fatalf("source auth methods mutated: %v", methods)
	}
}

func TestDiscoveryHandlerFiltersGeneratedDocument(t *testing.T) {
	t.Parallel()

	options := config_options.NewWicketOptions()
	handler := NewDiscoveryHandler(
		&fakeDiscoveryResponseGenerator{document: generatedDocument(false)},
		&fakeServerUrls{base: advertisementBaseUrl},
		&fakeIssuerNameService{issuer: advertisementBaseUrl},
		options,
		registeredEndpointPaths,
		noOpBackChannelLogout{},
		nil,
		quietLogger(),
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, advertisementBaseUrl+wicket.ProtocolRoutePathsDiscoveryConfiguration, nil)
	if err := handler.Process(recorder, request); err != nil {
		t.Fatalf("Process: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	for _, key := range []string{
		wicket.DiscoveryRevocationEndpoint,
		wicket.DiscoveryDeviceAuthorizationEndpoint,
		wicket.DiscoveryBackchannelLogoutSupported,
	} {
		if _, ok := document[key]; ok {
			t.Errorf("%s served by the handler, want it withdrawn", key)
		}
	}
	if _, ok := document[wicket.DiscoveryTokenEndpoint]; !ok {
		t.Errorf("%s missing from the served document", wicket.DiscoveryTokenEndpoint)
	}
}

func equalJson(t *testing.T, got any, want any) bool {
	t.Helper()
	left, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal %v: %v", got, err)
	}
	right, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal %v: %v", want, err)
	}
	return bytes.Equal(left, right)
}

// TestGeneratedDiscoveryKeysCoverTheDiscoveryConstants keeps the generated key
// name space in step with the wicket.Discovery* constants.
func TestGeneratedDiscoveryKeysCoverTheDiscoveryConstants(t *testing.T) {
	t.Parallel()

	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "constants.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse constants.go: %v", err)
	}
	want := map[string]struct{}{}
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for i, name := range value.Names {
				if !strings.HasPrefix(name.Name, "Discovery") || i >= len(value.Values) {
					continue
				}
				literal, ok := value.Values[i].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("%s is not a string literal constant", name.Name)
				}
				unquoted, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name.Name, err)
				}
				want[unquoted] = struct{}{}
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("no Discovery constants found in constants.go")
	}
	for key := range want {
		if _, ok := generatedDiscoveryKeys[key]; !ok {
			t.Errorf("generatedDiscoveryKeys misses %q", key)
		}
	}
	for key := range generatedDiscoveryKeys {
		if _, ok := want[key]; !ok {
			t.Errorf("generatedDiscoveryKeys holds %q which is not a Discovery constant", key)
		}
	}
}
