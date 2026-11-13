// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/extensions"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// BearerTokenUsageValidator Validates a request that uses a bearer token for authentication
type BearerTokenUsageValidator struct {
	logger *slog.Logger
}

// NewBearerTokenUsageValidator Initializes a new instance
func NewBearerTokenUsageValidator(logger *slog.Logger) *BearerTokenUsageValidator {
	return &BearerTokenUsageValidator{
		logger: logger,
	}
}

// Validate Validates the request.
func (v *BearerTokenUsageValidator) Validate(req *http.Request) (*validators_models.BearerTokenUsageValidationResult, error) {
	result := v.validateAuthorizationHeader(req)
	if result.TokenFound {
		v.logger.Debug("Bearer token found in header")
		return result, nil
	}

	if extensions.HasApplicationFormContentType(req) {
		result, err := v.validatePostBody(req)
		if err != nil {
			v.logger.Error("validatePostBody fail", slog.String("err", err.Error()))
			return nil, err
		}

		if result.TokenFound {
			v.logger.Debug("Bearer token found in body")
			return result, nil
		}
	}

	v.logger.Debug("Bearer token not found")
	return &validators_models.BearerTokenUsageValidationResult{}, nil
}

// validateAuthorizationHeader Validates the authorization header.
func (v *BearerTokenUsageValidator) validateAuthorizationHeader(req *http.Request) *validators_models.BearerTokenUsageValidationResult {
	header := strings.TrimSpace(req.Header.Get("Authorization"))
	if header != "" {
		if strings.HasPrefix(header, wicket.AuthenticationSchemesAuthorizationHeaderBearer) {
			value := strings.TrimSpace(strings.TrimPrefix(header, wicket.AuthenticationSchemesAuthorizationHeaderBearer))
			if value != "" {
				return &validators_models.BearerTokenUsageValidationResult{
					TokenFound: true,
					Token:      value,
					UsageType:  validators_models.AuthorizationHeader,
				}
			}
		} else {
			v.logger.Debug("Unexpected header format", slog.String("header", header))
		}
	}

	return &validators_models.BearerTokenUsageValidationResult{}
}

// validatePostBody Validates the post body.
func (v *BearerTokenUsageValidator) validatePostBody(req *http.Request) (*validators_models.BearerTokenUsageValidationResult, error) {
	var values url.Values
	if err := req.ParseForm(); err != nil {
		return nil, err
	}
	values = req.PostForm

	token := values.Get("access_token")
	if strings.TrimSpace(token) == "" {
		return &validators_models.BearerTokenUsageValidationResult{}, nil
	}

	return &validators_models.BearerTokenUsageValidationResult{
		TokenFound: true,
		Token:      token,
		UsageType:  validators_models.PostBody,
	}, nil
}
