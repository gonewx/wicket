// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// RefreshTokenProofBinding binds a refresh token to the key of a DPoP proof.
type RefreshTokenProofBinding struct {
	// DPoPKeyThumbprint is the RFC 7638 thumbprint of the DPoP proof key the
	// refresh token was issued with, or "" when the token is not bound. It
	// is written when the token is created and never changed. A bound token
	// is redeemed only with a proof made with the same key. A persistence
	// adapter has to keep this field; losing it unbinds the token.
	DPoPKeyThumbprint string
}
