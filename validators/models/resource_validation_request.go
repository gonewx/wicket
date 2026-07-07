// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	storage_models "github.com/gonewx/wicket/storage/models"
)

// Models the request to validate scopes and resource gaps for a client.
type ResourceValidationRequest struct {
	// The client.
	Client *storage_models.Client

	// The requested scope values.
	Scopes []string

	// The requested resource gaps.
	ResourceGaps []string

	// Flag that indicates that validation should allow requested scopes to match non-isolated resources.
	// If set to false, then only the scopes that match the exact resource gaps requested will be allowed.
	IncludeNonIsolatedApiResources bool
}
