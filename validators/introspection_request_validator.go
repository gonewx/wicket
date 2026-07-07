// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"net/url"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators/models"
)

// IntrospectionRequestValidator Interface for the introspection request validator
type IntrospectionRequestValidator interface {
	// Validates the request.
	Validate(parameters url.Values, api *storage_models.ApiResource) (*models.IntrospectionRequestValidationResult, error)
}
