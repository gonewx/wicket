// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"

	"github.com/gonewx/wicket"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// NotSupportedResourceOwnerPasswordValidator Default resource owner password validator (no implementation == not supported)
type NotSupportedResourceOwnerPasswordValidator struct {
	logger *slog.Logger
}

// / Initializes a new instance of the <see cref="NotSupportedResourceOwnerPasswordValidator"/> class.
func NewNotSupportedResourceOwnerPasswordValidator(logger *slog.Logger) *NotSupportedResourceOwnerPasswordValidator {
	return &NotSupportedResourceOwnerPasswordValidator{
		logger: logger,
	}
}

// / Validates the resource owner password credential
func (v *NotSupportedResourceOwnerPasswordValidator) Validate(ctx *validators_contexts.ResourceOwnerPasswordValidationContext) error {
	ctx.Result = validators_models.NewGrantValidationResult(
		validators_models.WithGrantValidationResultError(wicket.TokenRequestErrorsUnsupportedGrantType, ""),
	)

	v.logger.Info("Resource owner password credential type not supported. Configure an IResourceOwnerPasswordValidator.")
	return nil
}
