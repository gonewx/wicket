// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"net/url"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators/models"
)

// TokenRevocationRequestValidator Interface for the token revocation request validator
type TokenRevocationRequestValidator interface {
	// Validates the request.
	ValidateRequest(parameters url.Values, client *storage_models.Client) (*models.TokenRevocationRequestValidationResult, error)
}
