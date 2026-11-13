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

type TestResourceOwnerPasswordValidator struct {
	desc      string
	err       error
	sendError bool
}

func NewTestResourceOwnerPasswordValidator(err error, desc string) *TestResourceOwnerPasswordValidator {
	v := &TestResourceOwnerPasswordValidator{}
	if err != nil {
		v.err = err
		v.desc = desc
		v.sendError = true
	}

	return v
}

func (v *TestResourceOwnerPasswordValidator) Validate(ctx *validators_contexts.ResourceOwnerPasswordValidationContext) error {
	if v.sendError {
		ctx.Result = validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultError(wicket.TokenRequestErrorsInvalidGrant, v.desc),
		)
		return nil
	}

	if ctx.UserName == ctx.Password {
		ctx.Result = validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultSubject(ctx.UserName, "password", time.Now(), nil, wicket.LocalIdentityProvider, nil),
		)
	}

	if ctx.UserName == "bob_no_password" && ctx.Password == "" {
		ctx.Result = validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultSubject(ctx.UserName, "password", time.Now(), nil, wicket.LocalIdentityProvider, nil),
		)
	}

	return nil
}
