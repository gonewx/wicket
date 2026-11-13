// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/extensions"
	models_contexts "github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// UserInfoResponseGenerator The userinfo response generator
type UserInfoResponseGenerator struct {
	logger    *slog.Logger
	profile   services.ProfileService
	resources storage.ResourceStore
}

func NewUserInfoResponseGenerator(logger *slog.Logger, profile services.ProfileService, resources storage.ResourceStore) *UserInfoResponseGenerator {
	return &UserInfoResponseGenerator{
		logger:    logger,
		profile:   profile,
		resources: resources,
	}
}

// Processes the response.
func (g *UserInfoResponseGenerator) Handle(ctx context.Context, validationResult *validators_models.UserInfoRequestValidationResult) (map[string]any, error) {
	g.logger.Debug("Creating userinfo response")

	// extract scopes and turn into requested claim types
	scopes := utils.Select(
		utils.Where(validationResult.TokenValidationResult.Claims, func(c *claimspkg.Claim) bool {
			return c.Type == wicket.JwtClaimTypesScope
		}),
		func(c *claimspkg.Claim) string { return c.Value.(string) },
	)

	validatedResources := g.getRequestedResources(ctx, scopes)
	requestedClaimTypes := g.getRequestedClaimTypes(validatedResources)

	g.logger.Debug("Requested claim types", slog.String("claimTypes", strings.Join(requestedClaimTypes, " ")))

	// call profile service
	profileCtx := models_contexts.NewProfileDataRequestContext(
		validationResult.Subject,
		validationResult.TokenValidationResult.Client,
		wicket.ProfileDataCallersUserInfoEndpoint,
		requestedClaimTypes,
	)
	profileCtx.RequestedResources = validatedResources

	g.profile.GetProfileData(profileCtx)

	profileClaims := profileCtx.IssuedClaims

	// construct outgoing claims.
	outgoingClaims := make([]*claimspkg.Claim, 0)

	if profileClaims == nil {
		g.logger.Info("Profile service returned no claims. (null)")
	} else {
		outgoingClaims = append(outgoingClaims, profileClaims...)
		g.logger.Info("Profile service returned the following claim types", slog.String("types", strings.Join(utils.Select(profileClaims, func(c *claimspkg.Claim) string { return c.Type }), " ")))
	}

	subClaim := utils.SingleOrDefaultPred(outgoingClaims, func(x *claimspkg.Claim) bool { return x.Type == wicket.JwtClaimTypesSubject })
	if subClaim == nil {
		outgoingClaims = append(outgoingClaims, claimspkg.NewClaim(
			claimspkg.WithClaimType(wicket.JwtClaimTypesSubject),
			claimspkg.WithClaimValue(extensions.GetSubjectIdFromPrincipal(validationResult.Subject)),
		))
	} else {
		if subClaim.Value != extensions.GetSubjectIdFromPrincipal(validationResult.Subject) {
			g.logger.Error("Profile service returned incorrect subject value", slog.Any("sub", subClaim))
			return nil, fmt.Errorf("Profile service returned incorrect subject value: %w", wicket.InvalidOperationException)
		}
	}

	return extensions.ToClaimsMap(outgoingClaims), nil
}

func (g *UserInfoResponseGenerator) getRequestedResources(ctx context.Context, scopes []string) *validators_models.ResourceValidationResult {
	if len(scopes) == 0 {
		return nil
	}

	scopeString := strings.Join(scopes, " ")
	g.logger.Debug("Scopes in access token", slog.String("scopes", scopeString))

	// if we ever parameterized identity scopes, then we would need to invoke the resource validator's parse API here
	identityResources, err := extensions.FindEnabledIdentityResourcesByScope(ctx, g.resources, scopes)
	if err != nil {
		return nil
	}

	resources := storage_models.NewResources(
		storage_models.WithResourcesIdentityResources(identityResources),
		storage_models.WithResourcesApiResources(make([]*storage_models.ApiResource, 0)),
		storage_models.WithResourcesApiScopes(make([]*storage_models.ApiScope, 0)),
	)
	result := validators_models.NewResourceValidationResultWithResources(resources)

	return result
}

func (g *UserInfoResponseGenerator) getRequestedClaimTypes(resourceValidationResult *validators_models.ResourceValidationResult) []string {
	result := make([]string, 0)

	if resourceValidationResult == nil {
		return result
	}

	identityResources := resourceValidationResult.Resources.IdentityResources()
	result = utils.Distinct(
		utils.SelectMany(identityResources, func(x *storage_models.IdentityResource) []string { return x.UserClaims }),
	)

	return result
}
