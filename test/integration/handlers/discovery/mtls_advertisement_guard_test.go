// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package discovery

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientcert"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	integration_common "github.com/gonewx/wicket/test/integration/common"
	"github.com/gonewx/wicket/validators"
)

func enableEverySwitch(o *config_options.WicketOptions) {
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
}

func TestMutualTlsAdvertisementMatchesAnEnabledAssembly(t *testing.T) {
	t.Parallel()

	assemblies := []struct {
		name       string
		domainName string
	}{
		{name: "path form"},
		{name: "domain form", domainName: "mtls.wicket.test"},
	}
	for _, assembly := range assemblies {
		t.Run(assembly.name, func(t *testing.T) {
			t.Parallel()

			pipeline := integration_common.NewWicketPipeline()
			options := godi.GetRequired[*config_options.WicketOptions](pipeline.Root)
			enableEverySwitch(options)
			options.MutualTls.DomainName = assembly.domainName
			// An empty pool is enough to make tls_client_auth available.
			pipeline.Root.ServerConfig().EnableClientCertificateAuthentication(clientcert.Options{TrustedAuthorities: x509.NewCertPool()})
			pipeline.Initialize()
			t.Cleanup(pipeline.TestServer.Close)
			scope := pipeline.Root.CreateScope()
			t.Cleanup(func() { _ = scope.Close() })

			guard := &advertisementGuard{
				pipeline: pipeline,
				scope:    scope,
				document: fetchDiscoveryDocument(t, pipeline),
			}

			t.Run("both tls methods are advertised once", func(t *testing.T) {
				methods := stringList(guard.document[wicket.DiscoveryTokenEndpointAuthenticationMethodsSupported])
				for _, method := range []string{
					wicket.EndpointAuthenticationMethodsTlsClientAuth,
					wicket.EndpointAuthenticationMethodsSelfSignedTlsClientAuth,
				} {
					require.Equalf(t, 1, countOf(methods, method), "%s in %v", method, methods)
				}
				seen := map[string]bool{}
				for _, method := range methods {
					require.Falsef(t, seen[method], "%s listed twice in %v", method, methods)
					seen[method] = true
				}
			})
			t.Run("every alias is a valid URL routed to a handler", func(t *testing.T) {
				aliases, ok := guard.document[wicket.DiscoveryMtlsEndpointAliases].(map[string]any)
				require.True(t, ok, "mtls_endpoint_aliases missing")
				require.Len(t, aliases, 4)
				client := &http.Client{
					Transport: pipeline.TestServer.Client().Transport,
					CheckRedirect: func(*http.Request, []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				for name, value := range aliases {
					raw, ok := value.(string)
					require.Truef(t, ok, "alias %s is not a string", name)
					parsed, err := url.Parse(raw)
					require.NoErrorf(t, err, "alias %s = %q", name, raw)
					require.Truef(t, parsed.IsAbs() && parsed.Host != "", "alias %s = %q is not absolute", name, raw)
					if assembly.domainName != "" {
						require.Equal(t, assembly.domainName, parsed.Host)
					} else {
						require.Truef(t, strings.HasPrefix(raw, pipeline.TestServer.URL+"/"), "alias %s = %q", name, raw)
					}
					// The alias is requested at its path on the test server,
					// which stands in for the mutual TLS host.
					response, err := client.Get(pipeline.TestServer.URL + parsed.Path)
					require.NoError(t, err)
					_, _ = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
					require.NotEqualf(t, http.StatusNotFound, response.StatusCode, "alias %s = %q is not routed", name, raw)
				}
			})
			t.Run("certificate bound tokens are advertised", func(t *testing.T) {
				value, ok := guard.document[wicket.DiscoveryTlsClientCertificateBoundAccessTokens]
				require.True(t, ok)
				require.Equal(t, true, value)
			})
			t.Run("the existing guard holds", func(t *testing.T) {
				assertEndpointsRouted(t, guard)
				assertCapabilitiesBacked(t, guard)
				assertListsConsistent(t, guard)
				// In domain form the aliases name the main routes on the
				// mutual TLS host, so the path form alias routes, though
				// served, are not what the document advertises.
				if assembly.domainName == "" {
					assertRegisteredRoutesAdvertised(t, guard)
				}
			})
			t.Run("no mutual TLS warning is logged", func(t *testing.T) {
				logs := discoveryLogs(t, guard)
				require.NotContains(t, logs, "Mutual TLS is enabled")
			})
		})
	}
}

// discoveryLogs serves the discovery document once through a handler built
// from the assembly's own services, as the composition root builds it, but
// with a recording logger.
func discoveryLogs(t *testing.T, guard *advertisementGuard) string {
	t.Helper()
	pipeline := guard.pipeline
	paths := []string{}
	for _, endpoint := range godi.GetServices[*hosting.Endpoint](pipeline.Root) {
		paths = append(paths, endpoint.Path)
	}
	request := httptest.NewRequest(http.MethodGet, pipeline.TestServer.URL+integration_common.DiscoveryEndpoint, nil)
	logs := &bytes.Buffer{}
	handler := handlers.NewDiscoveryHandler(
		godi.GetRequired[responses.DiscoveryResponseGenerator](guard.scope),
		services_impl.NewServerUrls(request),
		godi.GetRequired[services.IssuerNameService](guard.scope),
		pipeline.Options,
		paths,
		godi.GetRequired[services.BackchannelLogoutService](guard.scope),
		godi.GetRequired[validators.SecretsListParser](guard.scope),
		slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	)
	handler.ServeClientCertificateAuthentication()
	recorder := httptest.NewRecorder()
	require.NoError(t, handler.Process(recorder, request))
	require.Equal(t, http.StatusOK, recorder.Code)
	var document map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &document))
	_, aliased := document[wicket.DiscoveryMtlsEndpointAliases]
	require.True(t, aliased, "the rebuilt handler withdrew the aliases")
	return logs.String()
}

func stringList(value any) []string {
	values, _ := value.([]any)
	out := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func countOf(values []string, want string) int {
	return len(slices.DeleteFunc(slices.Clone(values), func(value string) bool { return value != want }))
}
