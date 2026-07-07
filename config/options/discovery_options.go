// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package options

// Options class to configure discovery endpoint
type DiscoveryOptions struct {
	// Show endpoints
	ShowEndpoints bool

	// Show signing keys
	ShowKeySet bool

	// Show identity scopes
	ShowIdentityScopes bool

	// Show API scopes
	ShowApiScopes bool

	// Show identity claims.
	ShowClaims bool

	// Show response types
	ShowResponseTypes bool

	// Show response modes
	ShowResponseModes bool

	// Show standard grant types
	ShowGrantTypes bool

	// Show custom grant types
	ShowExtensionGrantTypes bool

	// Show token endpoint authentication methods
	ShowTokenEndpointAuthenticationMethods bool

	// Turns relative paths that start with ~/ into absolute paths
	ExpandRelativePathsInCustomEntries bool

	// Sets the maxage value of the cache control header (in seconds) of the HTTP response. This gives clients a hint how often they should refresh their cached copy of the discovery document. If set to 0 no-cache headers will be set. Defaults to null, which does not set the header.
	// The cache interval in seconds.
	ResponseCacheInterval *int

	// Adds custom entries to the discovery document
	CustomEntries map[string]any
}

func NewDiscoveryOptions() *DiscoveryOptions {
	return &DiscoveryOptions{
		ShowEndpoints:                          true,
		ShowKeySet:                             true,
		ShowIdentityScopes:                     true,
		ShowApiScopes:                          true,
		ShowClaims:                             true,
		ShowResponseModes:                      true,
		ShowResponseTypes:                      true,
		ShowGrantTypes:                         true,
		ShowExtensionGrantTypes:                true,
		ShowTokenEndpointAuthenticationMethods: true,
		ExpandRelativePathsInCustomEntries:     true,
		CustomEntries:                          make(map[string]any),
	}
}
