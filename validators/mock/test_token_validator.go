// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators/models"
)

type TestTokenValidator struct {
	result *models.TokenValidationResult
}

func NewTestTokenValidator(result *models.TokenValidationResult) *TestTokenValidator {
	return &TestTokenValidator{
		result: result,
	}
}

func (v *TestTokenValidator) ValidateAccessToken(token string, expectedScope string) *models.TokenValidationResult {
	return v.result
}

func (v *TestTokenValidator) ValidateIdentityToken(token string, clientId string, validateLifetime bool) *models.TokenValidationResult {
	return v.result
}

func (v *TestTokenValidator) ValidateRefreshToken(token string, client *storage_models.Client) *models.TokenValidationResult {
	return v.result
}
