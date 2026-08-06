// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	"github.com/gonewx/wicket/validators/models"
)

// IntrospectionRequestValidator Interface for the introspection request validator
type IntrospectionRequestValidator struct {
	logger         *slog.Logger
	tokenValidator validators.TokenValidator
}

func NewIntrospectionRequestValidator(tokenValidator validators.TokenValidator, logger *slog.Logger) *IntrospectionRequestValidator {
	return &IntrospectionRequestValidator{
		tokenValidator: tokenValidator,
		logger:         logger,
	}
}

// Validates the request.
func (v *IntrospectionRequestValidator) Validate(ctx context.Context, parameters url.Values, api *storage_models.ApiResource) (*models.IntrospectionRequestValidationResult, error) {
	v.logger.Debug("Introspection request validation started.")

	// retrieve required token
	token := parameters.Get("token")
	if token == "" {
		v.logger.Error("Token is missing")

		result := models.NewIntrospectionRequestValidationResult()
		result.Error = fmt.Errorf("missing_token")
		result.Api = api
		result.Parameters = parameters

		return result, nil
	}

	// validate token
	tokenValidationResult, err := v.tokenValidator.ValidateAccessToken(ctx, token, "")
	if err != nil {
		return nil, err
	}

	// invalid or unknown token
	if tokenValidationResult.Error != nil {
		v.logger.Debug("Token is invalid")

		result := models.NewIntrospectionRequestValidationResult()
		result.IsActive = false
		result.Token = token
		result.Api = api
		result.Parameters = parameters

		return result, nil
	}

	v.logger.Debug("Introspection request validation successful.")

	// valid token
	result := models.NewIntrospectionRequestValidationResult()
	result.IsActive = true
	result.Token = token
	result.Claims = tokenValidationResult.Claims
	result.Api = api
	result.Parameters = parameters

	return result, nil

}
