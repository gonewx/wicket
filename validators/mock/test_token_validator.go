// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"context"

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

func (v *TestTokenValidator) ValidateAccessToken(ctx context.Context, token string, expectedScope string) (*models.TokenValidationResult, error) {
	return v.result, nil
}

func (v *TestTokenValidator) ValidateIdentityToken(ctx context.Context, token string, clientId string, validateLifetime bool) (*models.TokenValidationResult, error) {
	return v.result, nil
}

func (v *TestTokenValidator) ValidateRefreshToken(ctx context.Context, token string, client *storage_models.Client) *models.TokenValidationResult {
	return v.result
}
