// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package test

import (
	"log/slog"

	"github.com/gonewx/wicket/extensions"
	models_contexts "github.com/gonewx/wicket/models/contexts"
)

type TestUserProfileService struct {
	logger *slog.Logger
	users  *TestUserStore
}

func NewTestUserProfileService(
	users *TestUserStore,
	logger *slog.Logger,
) *TestUserProfileService {
	return &TestUserProfileService{
		users:  users,
		logger: logger,
	}
}

// GetProfileData This method is called whenever claims about the user are requested (e.g. during token creation or via the userinfo endpoint)
func (s *TestUserProfileService) GetProfileData(ctx *models_contexts.ProfileDataRequestContext) {
	extensions.LogProfileRequest(ctx, s.logger)

	if len(ctx.RequestedClaimTypes) > 0 {
		user := s.users.FindBySubjectId(extensions.GetSubjectIdFromPrincipal(ctx.Subject))
		if user != nil {
			ctx.AddRequestedClaims(user.Claims)
		}
	}
	ctx.LogIssuedClaims(s.logger)
}

// IsActive This method gets called whenever identity server needs to determine if the user is valid or active (e.g. if the user's account has been deactivated since they logged in).
//
//	(e.g. during token issuance or validation).
func (s *TestUserProfileService) IsActive(ctx *models_contexts.IsActiveContext) {

	s.logger.Debug("IsActive called from: ", slog.String("caller", ctx.Caller))
	user := s.users.FindBySubjectId(extensions.GetSubjectIdFromPrincipal(ctx.Subject))
	if user != nil {
		ctx.IsActive = user.IsActive == true
	}
}
