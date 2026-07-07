// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators_contexts

import (
	"github.com/gonewx/wicket"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// / ExtensionGrantValidationContext describing the extension grant validation context
type ExtensionGrantValidationContext struct {
	/// Gets or sets the request.
	Request *validators_models.ValidatedTokenRequest

	/// Gets or sets the result.
	Result *validators_models.GrantValidationResult
}

func NewExtensionGrantValidationContext() *ExtensionGrantValidationContext {
	return &ExtensionGrantValidationContext{
		Result: validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultError(gois.TokenRequestErrorsInvalidGrant, ""),
		),
	}
}
