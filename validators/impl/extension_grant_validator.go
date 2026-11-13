// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"fmt"
	"log/slog"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// / Validates an extension grant request using the registered validators
type ExtensionGrantValidator struct {
	logger     *slog.Logger
	validators []validators.ExtensionGrantValidator
}

// / Gets the available grant types.
func (v *ExtensionGrantValidator) GetAvailableGrantTypes() []string {
	return utils.Select(v.validators, func(x validators.ExtensionGrantValidator) string {
		return x.GrantType()
	})
}

// Validates the request.
func (v *ExtensionGrantValidator) Validate(request *validators_models.ValidatedTokenRequest) *validators_models.GrantValidationResult {
	validator := utils.FirstOrDefaultPred(v.validators, func(x validators.ExtensionGrantValidator) bool {
		return x.GrantType() == request.GrantType
	})

	if validator == nil {
		v.logger.Error("No validator found for grant type")
		return validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultError(wicket.TokenRequestErrorsUnsupportedGrantType, ""),
		)
	}

	v.logger.Debug("Calling into custom grant validator", slog.String("type", fmt.Sprintf("%T", validator)))

	context := validators_contexts.NewExtensionGrantValidationContext()
	context.Request = request

	err := validator.Validate(context)
	if err != nil {
		v.logger.Error("Grant validation error", slog.String("message", err.Error()))
		return validators_models.NewGrantValidationResult(
			validators_models.WithGrantValidationResultError(wicket.TokenRequestErrorsInvalidGrant, ""),
		)

	}
	return context.Result
}

// Initializes a new instance of the <see cref="ExtensionGrantValidator"/> class.
func NewExtensionGrantValidator(validatorList []validators.ExtensionGrantValidator, logger *slog.Logger) *ExtensionGrantValidator {
	v := &ExtensionGrantValidator{}
	if validatorList == nil {
		v.validators = make([]validators.ExtensionGrantValidator, 0)
	} else {
		v.validators = validatorList
	}

	v.logger = logger

	return v
}
