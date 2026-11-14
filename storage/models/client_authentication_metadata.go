// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// ClientAuthenticationMetadata is the client authentication metadata a client
// registers. The field names follow the RFC 7591 client metadata names. The
// zero value means the client registered none of it and authenticates the way
// it always did.
type ClientAuthenticationMetadata struct {
	// TokenEndpointAuthMethod is "" when the client registered no method, or
	// "private_key_jwt" when it authenticates with a signed assertion.
	TokenEndpointAuthMethod string
	// Jwks is the inline JWK Set document (JSON text) holding the client's
	// public keys. It must not be set together with JwksUri.
	Jwks string
	// JwksUri is the pre-registered address of the client's JWK Set.
	JwksUri string
}
