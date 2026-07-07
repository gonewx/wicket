// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import storage_models "github.com/gonewx/wicket/storage/models"

// TokenRevocationRequestValidationResult Models the validation result of access tokens and id tokens.
type TokenRevocationRequestValidationResult struct {
	*ValidationResult

	// Gets or sets the token type hint.
	TokenTypeHint string

	/// Gets or sets the token.
	Token string

	/// Gets or sets the client.
	Client *storage_models.Client
}

// Initializes a new instance
func NewTokenRevocationRequestValidationResult() *TokenRevocationRequestValidationResult {
	r := &TokenRevocationRequestValidationResult{
		ValidationResult: NewValidationResult(),
	}
	return r
}
