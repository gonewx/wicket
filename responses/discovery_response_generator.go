// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package responses

import (
	"context"

	"github.com/gonewx/wicket/models"
)

// DiscoveryResponseGenerator Interface for discovery endpoint response generator
type DiscoveryResponseGenerator interface {
	// Creates the discovery document.
	CreateDiscoveryDocument(ctx context.Context, baseUrl string, issuerUri string) (map[string]any, error)

	// Creates the JWK document.
	CreateJwkDocument(ctx context.Context) ([]*models.JsonWebKey, error)
}
