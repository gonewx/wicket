// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"github.com/gonewx/wicket/claims"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type MockClaimsService struct {
	IdentityTokenClaims []*claims.Claim
	AccessTokenClaims   []*claims.Claim
}

func NewMockClaimsService() *MockClaimsService {
	return &MockClaimsService{}
}

func (s *MockClaimsService) GetIdentityTokenClaims(subject *claims.ClaimsPrincipal, resources *validators_models.ResourceValidationResult, includeAllIdentityClaims bool, request *validators_models.ValidatedRequest) ([]*claims.Claim, error) {
	return s.IdentityTokenClaims, nil
}

func (s *MockClaimsService) GetAccessTokenClaims(subject *claims.ClaimsPrincipal, resources *validators_models.ResourceValidationResult, request *validators_models.ValidatedRequest) ([]*claims.Claim, error) {
	return s.AccessTokenClaims, nil
}
