// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"crypto/subtle"

	"github.com/gonewx/wicket/dpop"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// refreshTokenProofBindingHolds reports whether a refresh token may be
// redeemed by the current request. A token bound to a DPoP proof key is
// redeemed only when the request presented an accepted proof made with that
// key; an unbound token is not judged. Whether the proof is missing or was
// made with another key is not told apart.
func refreshTokenProofBindingHolds(ctx context.Context, token *storage_models.RefreshToken) bool {
	if token == nil || token.DPoPKeyThumbprint == "" {
		return true
	}
	presented := dpop.ProofThumbprint(ctx)
	if presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(token.DPoPKeyThumbprint)) == 1
}

// authorizationCodeProofBindingHolds reports whether an authorization code
// that was already taken may be redeemed by the current request. A code
// bound with dpop_jkt is redeemed only when the request presented an
// accepted proof made with that key; an unbound code is not judged.
func authorizationCodeProofBindingHolds(ctx context.Context, code *storage_models.AuthorizationCode) bool {
	if code == nil || code.DPoPKeyThumbprint == "" {
		return true
	}
	presented := dpop.ProofThumbprint(ctx)
	if presented == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(code.DPoPKeyThumbprint)) == 1
}
