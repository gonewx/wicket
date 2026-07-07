// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"github.com/gonewx/wicket/models"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// ClientSecretValidationResult Validation result for client validation
type ClientSecretValidationResult struct {
	*ValidationResult

	// Gets or sets the client.
	Client *storage_models.Client

	// Gets or sets the secret used to authenticate the client.
	Secret *models.ParsedSecret

	// Gets or sets the value of the confirmation method (will become the cnf claim). Must be a JSON object.
	Confirmation string
}

func NewClientSecretValidationResult() *ClientSecretValidationResult {
	return &ClientSecretValidationResult{
		ValidationResult: NewValidationResult(),
	}
}
