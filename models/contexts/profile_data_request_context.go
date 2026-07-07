// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package contexts

import (
	"log/slog"
	"strings"

	claimspkg "github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ProfileDataRequestContext describing Profile data request
type ProfileDataRequestContext struct {
	// ValidatedRequest.
	ValidatedRequest *validators_models.ValidatedRequest

	// Subject.
	Subject *claimspkg.ClaimsPrincipal

	// Requested claim types.
	RequestedClaimTypes []string

	// Client.
	Client *storage_models.Client

	// Caller.
	Caller string

	// Resources.
	RequestedResources *validators_models.ResourceValidationResult

	// Issued models_
	IssuedClaims []*claimspkg.Claim
}

func NewProfileDataRequestContext(
	subject *claimspkg.ClaimsPrincipal,
	client *storage_models.Client,
	caller string,
	requestedClaimTypes []string,
) *ProfileDataRequestContext {
	return &ProfileDataRequestContext{
		Subject:             subject,
		Client:              client,
		Caller:              caller,
		RequestedClaimTypes: requestedClaimTypes,
	}
}

// FilterClaims
func (c *ProfileDataRequestContext) FilterClaims(claims []*claimspkg.Claim) []*claimspkg.Claim {
	return utils.Where(claims, func(x *claimspkg.Claim) bool {
		return utils.Contains(c.RequestedClaimTypes, x.Type)
	})
}

// AddRequestedClaims
func (c *ProfileDataRequestContext) AddRequestedClaims(claims []*claimspkg.Claim) {
	if len(c.RequestedClaimTypes) > 0 {
		c.IssuedClaims = append(c.IssuedClaims, c.FilterClaims(claims)...)
	}
}

// LogIssuedClaims Logs the issued claims.
func (c *ProfileDataRequestContext) LogIssuedClaims(logger *slog.Logger) {
	issuedClaims := utils.Select(c.IssuedClaims, func(c *claimspkg.Claim) string {
		return c.Type
	})
	logger.Debug("Issued claims",
		slog.String("claims", strings.Join(issuedClaims, " ")),
	)
}
