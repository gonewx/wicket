// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// AuthorizationCodeProofBinding binds an authorization code to the key of a
// DPoP proof (RFC 9449 section 10).
type AuthorizationCodeProofBinding struct {
	// DPoPKeyThumbprint is the RFC 7638 thumbprint of the DPoP key the
	// authorize request named with dpop_jkt, or "" when the code is not
	// bound. A bound code is redeemed only with a proof made with that key.
	// A persistence adapter has to keep this field; losing it unbinds the
	// code.
	DPoPKeyThumbprint string
}
