// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package setup

import (
	"log/slog"

	models_contexts "github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/test"
)

type CustomProfileService struct {
	*test.TestUserProfileService
}

func NewCustomProfileService(users *test.TestUserStore, logger *slog.Logger) *CustomProfileService {
	return &CustomProfileService{
		TestUserProfileService: test.NewTestUserProfileService(users, logger),
	}
}

func (s *CustomProfileService) GetProfileData(ctx *models_contexts.ProfileDataRequestContext) {
	s.TestUserProfileService.GetProfileData(ctx)

	if ctx.Subject.Identity().AuthenticationType() == "custom" {
		extraClaim := ctx.Subject.FindFirst("extra_claim")
		if extraClaim != nil {
			ctx.IssuedClaims = append(ctx.IssuedClaims, extraClaim)
		}
	}
}
