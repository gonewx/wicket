// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	models_contexts "github.com/gonewx/wicket/models/contexts"
)

type TestProfileService struct {
	shouldBeActive bool
}

func NewTestProfileService(shouldBeActive bool) *TestProfileService {
	return &TestProfileService{
		shouldBeActive: shouldBeActive,
	}
}

func (s *TestProfileService) GetProfileData(ctx *models_contexts.ProfileDataRequestContext) {
}

func (s *TestProfileService) IsActive(ctx *models_contexts.IsActiveContext) {
	ctx.IsActive = s.shouldBeActive
}
