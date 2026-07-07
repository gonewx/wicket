// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	storage_models "github.com/gonewx/wicket/storage/models"
)

// ApiSecretValidationResult Validation result for API validation
type ApiSecretValidationResult struct {
	*ValidationResult

	// Gets or sets the resource.
	Resource *storage_models.ApiResource
}

func NewApiSecretValidationResult() *ApiSecretValidationResult {
	return &ApiSecretValidationResult{
		ValidationResult: NewValidationResult(),
	}
}
