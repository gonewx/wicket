// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package test_handlers_endsession

import (
	"net/url"

	"github.com/gonewx/wicket/claims"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type StubEndSessionRequestValidator struct {
	EndSessionValidationResult         *validators_models.EndSessionValidationResult
	EndSessionCallbackValidationResult *validators_models.EndSessionCallbackValidationResult
}

func NewStubEndSessionRequestValidator() *StubEndSessionRequestValidator {
	return &StubEndSessionRequestValidator{
		EndSessionValidationResult:         validators_models.NewEndSessionValidationResult(),
		EndSessionCallbackValidationResult: validators_models.NewEndSessionCallbackValidationResult(),
	}
}

func (v *StubEndSessionRequestValidator) Validate(parameters url.Values, subject *claims.ClaimsPrincipal) (*validators_models.EndSessionValidationResult, error) {
	return v.EndSessionValidationResult, nil
}

func (v *StubEndSessionRequestValidator) ValidateCallback(parameters url.Values) (*validators_models.EndSessionCallbackValidationResult, error) {
	return v.EndSessionCallbackValidationResult, nil
}
