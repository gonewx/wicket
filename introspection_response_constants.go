// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

// JWT response for OAuth 2.0 token introspection (RFC 9701).
const (
	// MediaTypesTokenIntrospectionJwt is the media type a resource server
	// names in the Accept header to request a signed introspection response,
	// and the Content-Type of that response.
	MediaTypesTokenIntrospectionJwt = "application/token-introspection+jwt"
	// JwtTypesTokenIntrospection is the JOSE typ header of a signed
	// introspection response.
	JwtTypesTokenIntrospection = "token-introspection+jwt"
	// ClaimTypesTokenIntrospection is the claim of a signed introspection
	// response carrying the introspection result object.
	ClaimTypesTokenIntrospection = "token_introspection"
	// DiscoveryIntrospectionSigningAlgValuesSupported is the discovery
	// metadata name listing the algorithms that sign introspection
	// responses.
	DiscoveryIntrospectionSigningAlgValuesSupported = "introspection_signing_alg_values_supported"
)
