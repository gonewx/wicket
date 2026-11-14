// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// ClientAuthenticationMetadata is the client authentication metadata a client
// registers. The field names follow the RFC 7591 client metadata names. The
// zero value means the client registered none of it and authenticates the way
// it always did.
type ClientAuthenticationMetadata struct {
	// TokenEndpointAuthMethod is "" when the client registered no method,
	// "private_key_jwt" when it authenticates with a signed assertion,
	// "tls_client_auth" when it authenticates with a TLS client certificate
	// issued under a trusted authority and matched by exactly one of the
	// TlsClientAuth* fields, or "self_signed_tls_client_auth" when it
	// authenticates with a TLS client certificate registered as the first
	// x5c member of a key in Jwks.
	TokenEndpointAuthMethod string
	// Jwks is the inline JWK Set document (JSON text) holding the client's
	// public keys. It must not be set together with JwksUri.
	Jwks string
	// JwksUri is the pre-registered address of the client's JWK Set.
	JwksUri string
	// TlsClientAuthSubjectDn is the expected subject distinguished name of
	// the certificate of a tls_client_auth client, in the RFC 4514 string
	// form, compared character for character.
	TlsClientAuthSubjectDn string
	// TlsClientAuthSanDns is an expected dNSName subject alternative name.
	TlsClientAuthSanDns string
	// TlsClientAuthSanUri is an expected uniformResourceIdentifier subject
	// alternative name.
	TlsClientAuthSanUri string
	// TlsClientAuthSanIp is an expected iPAddress subject alternative name,
	// in textual IPv4 or IPv6 form.
	TlsClientAuthSanIp string
	// TlsClientAuthSanEmail is an expected rfc822Name subject alternative
	// name.
	TlsClientAuthSanEmail string
	// TlsClientCertificateBoundAccessTokens (RFC 8705 §3.4) asks for every
	// access token issued to the client at the token endpoint to be bound to
	// the client certificate presented with that token request: the token
	// carries the certificate's SHA-256 thumbprint under cnf / x5t#S256, and
	// a token request without a client certificate is refused. It is valid
	// only while mutual TLS client authentication is enabled, not for a
	// public client (RequireClientSecret false) and not together with
	// AllowAccessTokensViaBrowser.
	TlsClientCertificateBoundAccessTokens bool
}
