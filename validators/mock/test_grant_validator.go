// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package mock

import (
	"time"

	"github.com/gonewx/wicket"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type TestGrantValidator struct {
	isInvalid bool
	desc      string
}

func NewTestGrantValidator(isInvalid bool, desc string) *TestGrantValidator {
	return &TestGrantValidator{
		isInvalid: isInvalid,
		desc:      desc,
	}
}

func (v *TestGrantValidator) ValidateAsync(request *validators_models.ValidatedTokenRequest) (*validators_models.GrantValidationResult, error) {
	if v.isInvalid {
		return validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultError(wicket.TokenRequestErrorsInvalidGrant, v.desc),
		), nil
	}

	return validators_models.NewGrantValidationResult(
		validators_models.WithGrantValidationResultSubject("bob", "CustomGrant", time.Now(), nil, wicket.LocalIdentityProvider, nil),
	), nil
}

func (v *TestGrantValidator) Validate(ctx *validators_contexts.ExtensionGrantValidationContext) error {
	if v.isInvalid {
		ctx.Result = validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultError(wicket.TokenRequestErrorsInvalidGrant, v.desc),
		)
	} else {
		ctx.Result = validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultSubject("bob", "CustomGrant", time.Now(), nil, wicket.LocalIdentityProvider, nil),
		)
	}

	return nil
}

func (v *TestGrantValidator) GrantType() string {
	return "custom_grant"
}
