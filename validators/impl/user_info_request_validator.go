// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
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

// Validates a userinfo request. A non-nil error reports an infrastructure
// failure so the caller can distinguish it from a protocol-level invalid result.
func (v *UserInfoRequestValidator) ValidateRequest(ctx context.Context, accessToken string) (*validators_models.UserInfoRequestValidationResult, error) {
	result := validators_models.NewUserInfoRequestValidationResult()

	// the access token needs to be valid and have at least the openid scope
	tokenResult, err := v.tokenValidator.ValidateAccessToken(ctx, accessToken, wicket.StandardScopesOpenId)
	if err != nil {
		return nil, err
	}

	if tokenResult.Error != nil {
		result.Error = tokenResult.Error
		return result, nil
	}

	// the token must have a one sub claim
	subClaim := utils.SingleOrDefaultPred(tokenResult.Claims, func(c *claimspkg.Claim) bool {
		return c.Type == wicket.JwtClaimTypesSubject
	})
	if subClaim == nil {
		v.logger.Error("Token contains no sub claim")

		result.Error = wicket.ProtectedResourceErrorsInvalidToken
		return result, nil
	}

	// create subject from incoming access token
	claims := utils.Where(tokenResult.Claims, func(x *claimspkg.Claim) bool {
		return !utils.Contains(wicket.ProtocolClaimsFilter, x.Type)
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
	isActiveCtx := contexts.NewIsActiveContext(subject, tokenResult.Client, wicket.ProfileIsActiveCallersUserInfoRequestValidation)

	v.profile.IsActive(isActiveCtx)
	if !isActiveCtx.IsActive {
		v.logger.Error("User is not active", slog.String("sub", extensions.GetSubjectIdFromPrincipal(subject)))

		result.Error = wicket.ProtectedResourceErrorsInvalidToken
		return result, nil
	}

	result.TokenValidationResult = tokenResult
	result.Subject = subject

	return result, nil
}
