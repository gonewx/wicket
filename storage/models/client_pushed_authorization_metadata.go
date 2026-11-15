// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// ClientPushedAuthorizationMetadata is the pushed authorization request (RFC
// 9126) metadata a client registers. The zero value means the client may,
// but need not, push its authorization requests, and its request_uri handles
// live as long as the server default.
type ClientPushedAuthorizationMetadata struct {
	// RequirePushedAuthorizationRequests (RFC 9126 section 6) makes the
	// authorize endpoint accept the client's requests only through a pushed
	// request_uri. It is valid only while pushed authorization requests are
	// enabled.
	RequirePushedAuthorizationRequests bool
	// RequestUriLifetime is the entry lifetime, in seconds, of the
	// request_uri handles issued to the client. Zero means the server
	// default; a negative value is an invalid configuration.
	RequestUriLifetime int
}
