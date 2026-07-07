// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type MockResourceValidator struct {
	Result *validators_models.ResourceValidationResult
}

func NewMockResourceValidator() *MockResourceValidator {
	return &MockResourceValidator{}
}

func (v *MockResourceValidator) ParseRequestedScopes(scopeValues []string) []*validators_models.ParsedScopeValue {
	return utils.Select(scopeValues, func(x string) *validators_models.ParsedScopeValue {
		return &validators_models.ParsedScopeValue{RawValue: x}
	})
}

func (v *MockResourceValidator) ValidateRequestedResources(request *validators_models.ResourceValidationRequest) (*validators_models.ResourceValidationResult, error) {
	if v.Result == nil {
		v.Result = validators_models.NewResourceValidationResult()
	}
	return v.Result, nil
}
