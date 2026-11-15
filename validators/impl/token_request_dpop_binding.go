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
