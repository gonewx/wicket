// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators/models"
)

// TokenRevocationRequestValidator The token revocation request validator
type TokenRevocationRequestValidator struct {
	logger *slog.Logger
}

func NewTokenRevocationRequestValidator(logger *slog.Logger) *TokenRevocationRequestValidator {
	return &TokenRevocationRequestValidator{
		logger: logger,
	}
}

// Validates the request.
func (v *TokenRevocationRequestValidator) ValidateRequest(ctx context.Context, parameters url.Values, client *storage_models.Client) (*models.TokenRevocationRequestValidationResult, error) {
	v.logger.Debug("ValidateRequest called")

	if len(parameters) == 0 {
		v.logger.Error("no parameters passed")
		return nil, fmt.Errorf("no parameters passed")
	}

	if client == nil {
		v.logger.Error("no client passed")
		return nil, fmt.Errorf("no client passed")
	}

	result := models.NewTokenRevocationRequestValidationResult()

	// make sure token is present
	token := parameters.Get("token")
	if strings.TrimSpace(token) == "" {
		v.logger.Error("No token found in request")
		result.Error = wicket.TokenErrorsInvalidRequest
		return result, nil
	}

	result.Token = token
	result.Client = client

	// check token type hint
	hint := parameters.Get("token_type_hint")
	if strings.TrimSpace(hint) != "" {
		if utils.Contains(wicket.SupportedTokenTypeHints, hint) {
			v.logger.Debug("Token type hint found in request", slog.String("tokenTypeHint", hint))
			result.TokenTypeHint = hint
		} else {
			v.logger.Error("Invalid token type hint", slog.String("tokenTypeHint", hint))
			result.Error = wicket.RevocationErrorsUnsupportedTokenType
		}
	}

	v.logger.Debug("ValidateRequestAsync result", slog.Any("validateRequestResult", result))

	return result, nil
}
