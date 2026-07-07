// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// UserInfoRequestValidator Default userinfo request validator
type UserInfoRequestValidator struct {
	tokenValidator validators.TokenValidator
	profile        services.ProfileService
	logger         *slog.Logger
}

func NewUserInfoRequestValidator(
	tokenValidator validators.TokenValidator,
	profile services.ProfileService,
	logger *slog.Logger,
) *UserInfoRequestValidator {
	return &UserInfoRequestValidator{
		tokenValidator: tokenValidator,
		profile:        profile,
		logger:         logger,
	}
}

// Validates a userinfo request.
func (v *UserInfoRequestValidator) ValidateRequest(accessToken string) *validators_models.UserInfoRequestValidationResult {
	result := validators_models.NewUserInfoRequestValidationResult()

	// the access token needs to be valid and have at least the openid scope
	tokenResult := v.tokenValidator.ValidateAccessToken(accessToken, gois.StandardScopesOpenId)

	if tokenResult.Error != nil {
		result.Error = tokenResult.Error
		return result
	}

	// the token must have a one sub claim
	subClaim := utils.SingleOrDefaultPred(tokenResult.Claims, func(c *claimspkg.Claim) bool {
		return c.Type == gois.JwtClaimTypesSubject
	})
	if subClaim == nil {
		v.logger.Error("Token contains no sub claim")

		result.Error = gois.ProtectedResourceErrorsInvalidToken
		return result
	}

	// create subject from incoming access token
	claims := utils.Where(tokenResult.Claims, func(x *claimspkg.Claim) bool {
		return !utils.Contains(gois.ProtocolClaimsFilter, x.Type)
	})
	subject := claimspkg.NewClaimsPrincipal(
		claimspkg.WithClaimsPrincipalIdentity(
			claimspkg.NewClaimsIdentity(
				claimspkg.WithAuthenticationType("UserInfo"),
				claimspkg.WithClaims(claims),
			),
		),
	)

	// make sure user is still active
	isActiveCtx := contexts.NewIsActiveContext(subject, tokenResult.Client, gois.ProfileIsActiveCallersUserInfoRequestValidation)

	v.profile.IsActive(isActiveCtx)
	if !isActiveCtx.IsActive {
		v.logger.Error("User is not active", slog.String("sub", extensions.GetSubjectIdFromPrincipal(subject)))

		result.Error = gois.ProtectedResourceErrorsInvalidToken
		return result
	}

	result.TokenValidationResult = tokenResult
	result.Subject = subject

	return result
}
