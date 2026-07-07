// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// IntrospectionResponseGenerator introspection response generator
type IntrospectionResponseGenerator struct {
	// The logger
	logger *slog.Logger
}

// NewIntrospectionResponseGenerator creates a new introspection response generator
func NewIntrospectionResponseGenerator(logger *slog.Logger) *IntrospectionResponseGenerator {
	return &IntrospectionResponseGenerator{
		logger: logger,
	}
}

// Handle the response.
func (g *IntrospectionResponseGenerator) Handle(validationResult *validators_models.IntrospectionRequestValidationResult) map[string]any {
	g.logger.Debug("Creating introspection response")

	// standard response
	response := make(map[string]any, 0)
	response["active"] = false

	// token is invalid
	if !validationResult.IsActive {
		g.logger.Debug("Creating introspection response for inactive token.")
		return response
	}

	// expected scope not present
	if !g.areExpectedScopesPresent(validationResult) {
		return response
	}

	g.logger.Debug("Creating introspection response for active token.")

	// get all claims. (without scopes)
	response = utils.ToClaimsMap(utils.Where(validationResult.Claims, func(c *claims.Claim) bool {
		return c.Type != gois.JwtClaimTypesScope
	}))

	// add active flag
	response["active"] = true

	// calculate scopes the caller is allowed to see
	allowedScopes := validationResult.Api.Scopes
	scopes := utils.Select(
		utils.Where(validationResult.Claims, func(c *claims.Claim) bool { return c.Type == gois.JwtClaimTypesScope }),
		func(x *claims.Claim) string {
			if value, ok := x.Value.(string); ok {
				return value
			}
			return ""
		},
	)
	scopes = utils.Where(scopes, func(x string) bool {
		return utils.Contains(allowedScopes, x)
	})
	response["scope"] = strings.Join(scopes, " ")

	return response
}

// areExpectedScopesPresent Checks if the API resource is allowed to introspect the scopes.
func (g *IntrospectionResponseGenerator) areExpectedScopesPresent(validationResult *validators_models.IntrospectionRequestValidationResult) bool {
	apiScopes := validationResult.Api.Scopes
	tokenScopes := utils.Where(validationResult.Claims, func(c *claims.Claim) bool {
		return c.Type == gois.JwtClaimTypesScope
	})

	tokenScopesThatMatchApi := utils.Where(tokenScopes, func(c *claims.Claim) bool {
		value, _ := c.Value.(string)
		return utils.Contains(apiScopes, value)
	})

	result := false

	if len(tokenScopesThatMatchApi) > 0 {
		// at least one of the scopes the API supports is in the token
		result = true
	} else {
		// no scopes for this API are found in the token
		g.logger.Error("Expected scope {scopes} is missing in token", slog.String("scopes", strings.Join(apiScopes, ", ")))
	}

	return result
}
