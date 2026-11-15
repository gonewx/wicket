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
)

// registerAuthorizationServerMetadata wires the OAuth 2.0 authorization
// server metadata endpoint (RFC 8414). The handler is built on the discovery
// handler of the same assembly, so it serves the very document the OpenID
// Provider configuration serves, under the same enabling switch.
func registerAuthorizationServerMetadata() {
	var r godi.Registry

	godi.AddTransientFactory[*handlers.AuthorizationServerMetadataHandler](&r, func(p godi.Provider) *handlers.AuthorizationServerMetadataHandler {
		return handlers.NewAuthorizationServerMetadataHandler(newDiscoveryHandlerFromProvider(p))
	})

	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(wicket.EndpointNamesAuthorizationServerMetadata, wicket.ProtocolRoutePathsAuthorizationServerMetadata, endpointHandler[*handlers.AuthorizationServerMetadataHandler])
	})
}
