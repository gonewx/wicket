// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"context"

	"github.com/gonewx/wicket/storage/models"
)

// ClientOriginLookup finds the clients that list an origin among their allowed
// CORS origins. It is a separate port next to ClientStore: a host that injects
// a client store implements both on the same value so CORS decisions read the
// same client data as every other read path.
//
// The match is exact on AllowedCorsOrigins. The lookup neither filters on
// Enabled nor validates the configuration; the core side does both. A miss
// returns an empty slice and a nil error.
type ClientOriginLookup interface {
	FindClientsByAllowedOrigin(ctx context.Context, origin string) ([]*models.Client, error)
}
