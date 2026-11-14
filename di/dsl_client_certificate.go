// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/validators"
)

// registerClientCertificate wires mutual TLS client authentication. The alias
// routes are singletons built with the root container, before the host can
// declare the feature, so their handler functions read the declaration on
// every request and yield no handler while the feature is not enabled. The
// method parsers are transient and read the declaration when resolved.
func registerClientCertificate() {
	var r godi.Registry

	godi.AddTransientFactory[validators.SecretParser](&r, tlsClientAuthSecretParserFromProvider)
	godi.AddTransientFactory[validators.SecretParser](&r, selfSignedTlsClientAuthSecretParserFromProvider)

	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(wicket.EndpointNamesToken, wicket.ProtocolRoutePathsMtlsToken, mtlsEndpointHandler[*handlers.TokenHandler])
	})
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(wicket.EndpointNamesRevocation, wicket.ProtocolRoutePathsMtlsRevocation, mtlsEndpointHandler[*handlers.TokenRevocationHandler])
	})
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(wicket.EndpointNamesIntrospection, wicket.ProtocolRoutePathsMtlsIntrospection, mtlsEndpointHandler[*handlers.IntrospectionHandler])
	})
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(wicket.EndpointNamesDeviceAuthorization, wicket.ProtocolRoutePathsMtlsDeviceAuthorization, mtlsEndpointHandler[*handlers.DeviceAuthorizationHandler])
	})
}
