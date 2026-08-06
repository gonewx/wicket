// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"context"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators/models"
)

type StubTokenValidator struct {
	AccessTokenValidationResult   *models.TokenValidationResult
	IdentityTokenValidationResult *models.TokenValidationResult
}

func NewStubTokenValidator() *StubTokenValidator {
	return &StubTokenValidator{
		AccessTokenValidationResult:   models.NewTokenValidationResult(),
		IdentityTokenValidationResult: models.NewTokenValidationResult(),
	}
}

func (v *StubTokenValidator) ValidateAccessToken(ctx context.Context, token string, expectedScope string) (*models.TokenValidationResult, error) {
	return v.AccessTokenValidationResult, nil
}

func (v *StubTokenValidator) ValidateIdentityToken(ctx context.Context, token string, clientId string, validateLifetime bool) (*models.TokenValidationResult, error) {
	return v.IdentityTokenValidationResult, nil
}

func (v *StubTokenValidator) ValidateRefreshToken(ctx context.Context, token string, client *storage_models.Client) *models.TokenValidationResult {
	return nil
}
