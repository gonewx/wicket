// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators_contexts

import (
	"github.com/gonewx/wicket"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ResourceOwnerPasswordValidationContext describing the resource owner password validation context
type ResourceOwnerPasswordValidationContext struct {
	// Gets or sets the name of the user.
	// The name of the user.
	UserName string

	// Gets or sets the password.
	// The password.
	Password string

	// Gets or sets the request.
	// The request.
	Request *validators_models.ValidatedTokenRequest

	// Gets or sets the result.
	// The result.
	Result *validators_models.GrantValidationResult
}

func NewResourceOwnerPasswordValidationContext() *ResourceOwnerPasswordValidationContext {
	return &ResourceOwnerPasswordValidationContext{
		Result: validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultError(wicket.TokenRequestErrorsInvalidGrant, ""),
		),
	}

}
