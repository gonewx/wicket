// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package authorize

import (
	"net/url"

	"github.com/gonewx/wicket/claims"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type StubAuthorizeRequestValidator struct {
	Result *validators_models.AuthorizeRequestValidationResult
}

func NewStubAuthorizeRequestValidator() *StubAuthorizeRequestValidator {
	return &StubAuthorizeRequestValidator{
		Result: validators_models.NewAuthorizeRequestValidationResult(validators_models.NewValidatedAuthorizeRequest()),
	}
}

func (v *StubAuthorizeRequestValidator) Validate(values url.Values, user *claims.ClaimsPrincipal) *validators_models.AuthorizeRequestValidationResult {
	v.Result.ValidatedRequest.Raw = values
	return v.Result
}
