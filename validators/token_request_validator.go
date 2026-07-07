// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"net/url"

	"github.com/gonewx/wicket/validators/models"
)

// TokenRequestValidator Interface for the token request validator
type TokenRequestValidator interface {
	// Validates the request.
	ValidateRequest(parameters url.Values, clientValidationResult *models.ClientSecretValidationResult) *models.TokenRequestValidationResult
}
