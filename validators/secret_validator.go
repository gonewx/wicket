// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
	validtors_models "github.com/gonewx/wicket/validators/models"
)

// SecretValidator Service for validating a received secret against a stored secret
type SecretValidator interface {
	// Validates a secret
	// <param name="secrets">The stored secrets.</param>
	// <param name="parsedSecret">The received secret.</param>
	Validate(secrets []*storage_models.Secret, parsedSecret *models.ParsedSecret) (*validtors_models.SecretValidationResult, error)
}
