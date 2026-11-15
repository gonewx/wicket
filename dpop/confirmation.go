// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"context"
	"net/http"

	"github.com/gonewx/wicket/services"
)

// AccessTokenBinder binds an access token to the key of the proof accepted
// for the request that issues it (RFC 9449 jkt confirmation). A request
// without an accepted proof leaves the token unbound.
type AccessTokenBinder struct{}

var _ services.AccessTokenConfirmation = AccessTokenBinder{}

// NewAccessTokenBinder returns the binder.
func NewAccessTokenBinder() AccessTokenBinder {
	return AccessTokenBinder{}
}

// Confirmation returns {"jkt":"<thumbprint>"} when ctx carries the
// thumbprint of an accepted proof and "" otherwise. It never fails.
func (AccessTokenBinder) Confirmation(ctx context.Context, _ *http.Request, _ string) (string, error) {
	thumbprint := ProofThumbprint(ctx)
	if thumbprint == "" {
		return "", nil
	}
	return Confirmation(thumbprint), nil
}
