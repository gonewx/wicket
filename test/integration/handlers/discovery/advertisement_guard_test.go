// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package discovery

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/services"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/validators"
)

// backChannelLogoutDelivery is the method a back-channel logout service
// exposes once it actually delivers logout notifications.
type backChannelLogoutDelivery interface {
	DeliversBackChannelLogout() bool
}

// advertisementGuard holds what the guard needs to judge one assembly.
type advertisementGuard struct {
	pipeline *integration_common.WicketPipeline
	scope    godi.Scope
	document map[string]any
}

func (g *advertisementGuard) options() *config_options.WicketOptions {
	return g.pipeline.Options
}

func (g *advertisementGuard) routeRegistered(path string) bool {
	for _, endpoint := range godi.GetServices[*hosting.Endpoint](g.pipeline.Root) {
		if strings.EqualFold(endpoint.Path, "/"+strings.TrimLeft(path, "/")) {
			return true
		}
	}
	return false
}

func (g *advertisementGuard) advertised(key string) bool {
	_, ok := g.document[key]
	return ok
}

func (g *advertisementGuard) serverConfig() *di.ServerConfig {
	return g.pipeline.Root.ServerConfig()
}

func (g *advertisementGuard) authenticationMethods() []string {
	return godi.GetRequired[validators.SecretsListParser](g.scope).GetAvailableAuthenticationMethods()
}

// capabilityEvidence maps every capability key the document may set to true
// onto the check proving the running assembly implements it. A true key that
// is missing from this table fails the guard.
var capabilityEvidence = map[string]func(*advertisementGuard) bool{
	wicket.DiscoveryFrontChannelLogoutSupported: func(g *advertisementGuard) bool {
		return g.advertised(wicket.DiscoveryEndSessionEndpoint) && g.routeRegistered(wicket.ProtocolRoutePathsEndSessionCallback)
	},
	wicket.DiscoveryFrontChannelLogoutSessionSupported: func(g *advertisementGuard) bool {
		return g.advertised(wicket.DiscoveryEndSessionEndpoint) && g.routeRegistered(wicket.ProtocolRoutePathsEndSessionCallback)
	},
	wicket.DiscoveryBackchannelLogoutSupported: func(g *advertisementGuard) bool {
		return deliversBackChannelLogout(g)
	},
	wicket.DiscoveryBackchannelLogoutSessionSupported: func(g *advertisementGuard) bool {
		return deliversBackChannelLogout(g)
	},
	wicket.DiscoveryRequestParameterSupported: func(g *advertisementGuard) bool {
		return g.routeRegistered(wicket.ProtocolRoutePathsAuthorize) &&
			godi.GetRequired[validators.JwtRequestValidator](g.scope) != nil
	},
	wicket.DiscoveryRequestUriParameterSupported: func(g *advertisementGuard) bool {
		return g.options().Endpoints.EnableJwtRequestUri &&
			g.routeRegistered(wicket.ProtocolRoutePathsAuthorize) &&
			godi.GetRequired[services.JwtRequestUriHttpClient](g.scope) != nil
	},
	wicket.DiscoveryAuthorizationResponseIssParameterSupported: func(g *advertisementGuard) bool {
		return g.options().EmitIssuerIdentificationResponseParameter
	},
	wicket.DiscoveryBackchannelUserCodeParameterSupported: func(g *advertisementGuard) bool {
		return g.routeRegistered(wicket.ProtocolRoutePathsBackchannelAuthentication) &&
			godi.GetRequired[validators.BackchannelAuthenticationRequestValidator](g.scope) != nil
	},
	// dpop_signing_alg_values_supported is a list, never true; its
	// agreement with the assembly is checked by assertListsConsistent.
	wicket.DiscoveryDPoPSigningAlgValuesSupported: func(g *advertisementGuard) bool {
		return g.serverConfig().DPoPEnabled()
	},
	wicket.DiscoveryTlsClientCertificateBoundAccessTokens: func(g *advertisementGuard) bool {
		return slices.ContainsFunc(g.authenticationMethods(), func(method string) bool {
			return method == wicket.EndpointAuthenticationMethodsTlsClientAuth ||
				method == wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth
		})
	},
}

func deliversBackChannelLogout(g *advertisementGuard) bool {
	service := godi.GetRequired[services.BackchannelLogoutService](g.scope)
	delivery, ok := service.(backChannelLogoutDelivery)
	return ok && delivery.DeliversBackChannelLogout()
}

func isEndpointAdvertisement(key string) bool {
	return strings.HasSuffix(key, "_endpoint") ||
		key == wicket.DiscoveryCheckSessionIframe ||
		key == wicket.DiscoveryJwksUri
}

func TestDiscoveryAdvertisementMatchesTheAssembly(t *testing.T) {
	t.Parallel()

	assemblies := []struct {
		name      string
		configure func(*config_options.WicketOptions)
		// declare runs on the pipeline before it is initialized.
		declare func(*integration_common.WicketPipeline)
	}{
		{name: "default assembly"},
		{
			name: "pushed authorization enabled",
			declare: func(p *integration_common.WicketPipeline) {
				p.EnablePushedAuthorization(pushedauth.Options{RequireForAllClients: true})
			},
		},
		{
			name: "dpop enabled",
			declare: func(p *integration_common.WicketPipeline) {
				cfg := p.Root.ServerConfig()
				cfg.SetReplayRegistry(replay.NewMemoryRegistry())
				cfg.EnableDPoP(dpop.Options{SigningAlgorithms: []string{"ES256", "RS256"}})
			},
		},
		{
			name: "every switch on",
			configure: func(o *config_options.WicketOptions) {
				o.Endpoints.EnableAuthorizeEndpoint = true
				o.Endpoints.EnableJwtRequestUri = true
				o.Endpoints.EnableTokenEndpoint = true
				o.Endpoints.EnableUserInfoEndpoint = true
				o.Endpoints.EnableDiscoveryEndpoint = true
				o.Endpoints.EnableEndSessionEndpoint = true
				o.Endpoints.EnableCheckSessionEndpoint = true
				o.Endpoints.EnableTokenRevocationEndpoint = true
				o.Endpoints.EnableIntrospectionEndpoint = true
				o.Endpoints.EnableDeviceAuthorizationEndpoint = true
				o.Endpoints.EnableBackchannelAuthenticationEndpoint = true
				o.MutualTls.Enabled = true
			},
		},
	}

	for _, assembly := range assemblies {
		t.Run(assembly.name, func(t *testing.T) {
			t.Parallel()

			pipeline := integration_common.NewWicketPipeline()
			if assembly.declare != nil {
				assembly.declare(pipeline)
			}
			pipeline.Initialize()
			t.Cleanup(pipeline.TestServer.Close)
			if assembly.configure != nil {
				assembly.configure(pipeline.Options)
			}
			scope := pipeline.Root.CreateScope()
			t.Cleanup(func() { _ = scope.Close() })

			configuration := fetchDiscoveryDocument(t, pipeline)
			metadata := fetchMetadataDocument(t, pipeline, wicket.ProtocolRoutePathsAuthorizationServerMetadata)

			t.Run("both documents carry the same keys and values", func(t *testing.T) {
				assertDocumentsAgree(t, configuration, metadata)
			})

			documents := []struct {
				name     string
				document map[string]any
			}{
				{name: "openid configuration", document: configuration},
				{name: "authorization server metadata", document: metadata},
			}
			for _, document := range documents {
				t.Run(document.name, func(t *testing.T) {
					guard := &advertisementGuard{
						pipeline: pipeline,
						scope:    scope,
						document: document.document,
					}

					t.Run("every advertised endpoint is routed", func(t *testing.T) {
						assertEndpointsRouted(t, guard)
					})
					t.Run("every advertised capability has evidence", func(t *testing.T) {
						assertCapabilitiesBacked(t, guard)
					})
					t.Run("advertised lists agree with the assembly", func(t *testing.T) {
						assertListsConsistent(t, guard)
					})
					t.Run("every registered route is advertised", func(t *testing.T) {
						assertRegisteredRoutesAdvertised(t, guard)
					})
				})
			}
		})
	}
}

// assertDocumentsAgree requires the authorization server metadata document
// to carry exactly the keys of the OpenID Provider configuration, each with
// the same value.
func assertDocumentsAgree(t *testing.T, configuration, metadata map[string]any) {
	t.Helper()

	configurationKeys := slices.Sorted(maps.Keys(configuration))
	metadataKeys := slices.Sorted(maps.Keys(metadata))
	require.Equal(t, configurationKeys, metadataKeys, "the two documents carry different keys")
	for _, key := range configurationKeys {
		require.Equalf(t, configuration[key], metadata[key], "%s differs between the two documents", key)
	}
}

func fetchDiscoveryDocument(t *testing.T, pipeline *integration_common.WicketPipeline) map[string]any {
	t.Helper()

	return fetchMetadataDocument(t, pipeline, integration_common.DiscoveryEndpoint)
}

func fetchMetadataDocument(t *testing.T, pipeline *integration_common.WicketPipeline, path string) map[string]any {
	t.Helper()

	response, err := pipeline.TestServer.Client().Get(pipeline.TestServer.URL + path)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)

	var document map[string]any
	require.NoError(t, json.NewDecoder(response.Body).Decode(&document))
	return document
}

func assertEndpointsRouted(t *testing.T, guard *advertisementGuard) {
	t.Helper()

	base := guard.pipeline.TestServer.URL
	var urls []string
	for key, value := range guard.document {
		if !isEndpointAdvertisement(key) {
			continue
		}
		raw, ok := value.(string)
		require.Truef(t, ok, "%s is not a URL string: %v", key, value)
		if !strings.HasPrefix(raw, base+"/") {
			// external URLs are advertised as they are; another host serves them
			continue
		}
		urls = append(urls, raw)
	}
	if aliases, ok := guard.document[wicket.DiscoveryMtlsEndpointAliases].(map[string]any); ok {
		for name, value := range aliases {
			raw, ok := value.(string)
			require.Truef(t, ok, "mtls alias %s is not a URL string: %v", name, value)
			if local, ok := localAliasUrl(guard, raw); ok {
				urls = append(urls, local)
			}
		}
	}
	require.NotEmpty(t, urls)

	client := &http.Client{
		Transport: guard.pipeline.TestServer.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, raw := range urls {
		response, err := client.Get(raw)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		require.NotEqualf(t, http.StatusNotFound, response.StatusCode, "advertised URL %s is not routed", raw)
	}
}

// localAliasUrl reads an mtls alias the way the discovery filter does. Without
// a mutual TLS domain name an alias is in path form: it is built by appending
// the route to the base URL, where the separating slash may be missing, so
// any alias starting with the base URL is local and is requested at the base
// URL plus its route path. With a domain name the alias lives on another host
// unless it is a plain URL under the base URL.
func localAliasUrl(guard *advertisementGuard, raw string) (string, bool) {
	base := guard.pipeline.TestServer.URL
	if guard.options().MutualTls.DomainName != "" {
		return raw, strings.HasPrefix(raw, base+"/")
	}
	rest, ok := strings.CutPrefix(raw, base)
	if !ok {
		return "", false
	}
	return base + "/" + strings.TrimLeft(rest, "/"), true
}

func assertCapabilitiesBacked(t *testing.T, guard *advertisementGuard) {
	t.Helper()

	for key, value := range guard.document {
		if !strings.HasSuffix(key, "_supported") && key != wicket.DiscoveryTlsClientCertificateBoundAccessTokens {
			continue
		}
		enabled, ok := value.(bool)
		if !ok || !enabled {
			continue
		}
		evidence, known := capabilityEvidence[key]
		require.Truef(t, known, "%s is advertised as true but has no entry in the capability evidence table", key)
		require.Truef(t, evidence(guard), "%s is advertised as true but the assembly does not implement it", key)
	}
}

func assertListsConsistent(t *testing.T, guard *advertisementGuard) {
	t.Helper()

	if grantTypes, ok := guard.document[wicket.DiscoveryGrantTypesSupported].([]any); ok {
		if slices.Contains(grantTypes, any(wicket.GrantTypeDeviceCode)) {
			require.Truef(t, guard.advertised(wicket.DiscoveryDeviceAuthorizationEndpoint),
				"%s advertises %s without %s", wicket.DiscoveryGrantTypesSupported, wicket.GrantTypeDeviceCode, wicket.DiscoveryDeviceAuthorizationEndpoint)
		}
	}

	// DPoP proof algorithms are advertised exactly while DPoP is enabled,
	// and then as the configured list.
	dpopAlgorithms, dpopAdvertised := guard.document[wicket.DiscoveryDPoPSigningAlgValuesSupported]
	require.Equalf(t, guard.serverConfig().DPoPEnabled(), dpopAdvertised,
		"%s advertised = %v, DPoP enabled = %v", wicket.DiscoveryDPoPSigningAlgValuesSupported, dpopAdvertised, guard.serverConfig().DPoPEnabled())
	if dpopAdvertised {
		want := make([]any, 0)
		for _, algorithm := range guard.serverConfig().DPoPOptions().SigningAlgorithms {
			want = append(want, algorithm)
		}
		require.Equalf(t, want, dpopAlgorithms, "%s does not list the configured algorithms", wicket.DiscoveryDPoPSigningAlgValuesSupported)
	}

	if methods, ok := guard.document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported].([]any); ok {
		available := guard.authenticationMethods()
		for _, method := range methods {
			name, ok := method.(string)
			require.Truef(t, ok, "authentication method is not a string: %v", method)
			require.Containsf(t, available, name, "%s advertises %s which no registered secret parser provides",
				wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported, name)
		}
	}
}

// unadvertisedRoutes are registered routes that no discovery key describes:
// the discovery document, the authorization server metadata document and the
// interaction callbacks.
var unadvertisedRoutes = []string{
	wicket.ProtocolRoutePathsDiscoveryConfiguration,
	wicket.ProtocolRoutePathsAuthorizationServerMetadata,
	"/" + wicket.ProtocolRoutePathsAuthorizeCallback,
	"/" + wicket.ProtocolRoutePathsEndSessionCallback,
}

func assertRegisteredRoutesAdvertised(t *testing.T, guard *advertisementGuard) {
	t.Helper()

	featureGatedRoutes := []string{
		"/" + wicket.ProtocolRoutePathsMtlsToken,
		"/" + wicket.ProtocolRoutePathsMtlsRevocation,
		"/" + wicket.ProtocolRoutePathsMtlsIntrospection,
		"/" + wicket.ProtocolRoutePathsMtlsDeviceAuthorization,
		"/" + wicket.ProtocolRoutePathsPushedAuthorization,
		"/" + wicket.ProtocolRoutePathsMtlsPushedAuthorization,
	}

	advertisedUrls := map[string]struct{}{}
	for _, value := range guard.document {
		if raw, ok := value.(string); ok {
			advertisedUrls[raw] = struct{}{}
		}
	}
	if aliases, ok := guard.document[wicket.DiscoveryMtlsEndpointAliases].(map[string]any); ok {
		for _, value := range aliases {
			raw, ok := value.(string)
			if !ok {
				continue
			}
			advertisedUrls[raw] = struct{}{}
			if local, ok := localAliasUrl(guard, raw); ok {
				advertisedUrls[local] = struct{}{}
			}
		}
	}

	endpoints := godi.GetServices[*hosting.Endpoint](guard.pipeline.Root)
	require.NotEmpty(t, endpoints)
	for _, endpoint := range endpoints {
		if slices.ContainsFunc(unadvertisedRoutes, func(path string) bool { return strings.EqualFold(path, endpoint.Path) }) {
			continue
		}
		// The mtls alias routes and the pushed authorization routes are
		// registered with the root container and yield no handler until the
		// host enables mutual TLS client authentication or pushed
		// authorization requests; the request then falls through to the next
		// handler, so this assembly does not serve them. Only these routes
		// are exempted, and only while they yield no handler.
		if slices.Contains(featureGatedRoutes, endpoint.Path) {
			if handler, err := endpoint.Handler(guard.scope); err == nil && handler == nil {
				continue
			}
		}
		want := guard.pipeline.TestServer.URL + endpoint.Path
		_, ok := advertisedUrls[want]
		require.Truef(t, ok, "registered route %s (%s) is not advertised as %s", endpoint.Name, endpoint.Path, want)
	}
}
