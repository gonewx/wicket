// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"github.com/gonewx/wicket/claims"
	models_contexts "github.com/gonewx/wicket/models/contexts"
)

type MockProfileService struct {
	ProfileClaims []*claims.Claim
	isActive      bool

	ProfileContext *models_contexts.ProfileDataRequestContext

	ActiveContext *models_contexts.IsActiveContext
}

func NewMockProfileService() *MockProfileService {
	return &MockProfileService{
		isActive:      true,
		ProfileClaims: make([]*claims.Claim, 0),
	}
}

func (s *MockProfileService) GetProfileData(ctx *models_contexts.ProfileDataRequestContext) {

	s.ProfileContext = ctx
	ctx.IssuedClaims = s.ProfileClaims
}

func (s *MockProfileService) IsActive(ctx *models_contexts.IsActiveContext) {

	s.ActiveContext = ctx
	ctx.IsActive = s.isActive
}

func (s *MockProfileService) GetProfileWasCalled() bool {
	return s.ProfileContext != nil
}

func (s *MockProfileService) IsActiveWasCalled() bool {
	return s.ActiveContext != nil
}
