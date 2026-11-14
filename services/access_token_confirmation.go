// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package services

import (
	"context"
	"net/http"
)

// AccessTokenConfirmation decides the confirmation an access token carries.
// It is consulted for every access token serialized, whatever endpoint
// issues it.
type AccessTokenConfirmation interface {
	// Confirmation returns the confirmation of an access token issued to
	// clientId in response to request. The value is written to
	// Token.Confirmation and so becomes the token's cnf claim; "" means the
	// token is not bound. An error refuses issuing the token.
	Confirmation(ctx context.Context, request *http.Request, clientId string) (string, error)
}
