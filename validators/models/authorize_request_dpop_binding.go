// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// AuthorizeRequestProofBinding is the DPoP key an authorize request binds
// its authorization code to (RFC 9449 section 10).
type AuthorizeRequestProofBinding struct {
	// DPoPKeyThumbprint is the dpop_jkt parameter: the RFC 7638 SHA-256
	// thumbprint of the DPoP key, or "" when the request names none or DPoP
	// is not enabled.
	DPoPKeyThumbprint string
}
