// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	storage "github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
	"github.com/gonewx/wicket/validators/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ApiSecretValidator Validates API secrets using the registered secret validators and parsers
type ApiSecretValidator struct {
	logger    *slog.Logger
	resources storage.ResourceStore
	parser    validators.SecretsListParser
	validator validators.SecretsListValidator
}

func NewApiSecretValidator(
	resources storage.ResourceStore,
	parser validators.SecretsListParser,
	validator validators.SecretsListValidator,
	logger *slog.Logger,
) *ApiSecretValidator {
	return &ApiSecretValidator{
		resources: resources,
		parser:    parser,
		validator: validator,
		logger:    logger,
	}
}

// Validate Validates the secret on the current request.
func (v *ApiSecretValidator) Validate(req *http.Request) *models.ApiSecretValidationResult {
	v.logger.Debug("Start API validation")

	fail := validators_models.NewApiSecretValidationResult()
	fail.Error = wicket.TokenErrorsInvalidRequest

	parsedSecret, err := v.parser.Parse(req)
	if err != nil || parsedSecret == nil {
		v.logger.Error("No API secret found")

		fail.Error = wicket.TokenErrorsInvalidRequest
		return fail
	}

	// load API resource
	apis, err := v.resources.FindApiResourcesByName(req.Context(), []string{parsedSecret.Id})
	if err != nil || apis == nil || len(apis) == 0 {
		v.logger.Error("No API resource with that name found. aborting")
		return fail
	}

	if len(apis) > 1 {
		v.logger.Error("More than one API resource with that name found. aborting")
		return fail
	}

	api := apis[0]

	if !api.Enabled {
		v.logger.Error("API resource not enabled. aborting.")
		return fail
	}

	result, err := v.validator.Validate(api.ApiSecrets, parsedSecret)
	if err != nil || result == nil || !result.Success {
		v.logger.Error("API validation failed.")
		return fail
	}

	v.logger.Error("API resource validation success")

	success := validators_models.NewApiSecretValidationResult()
	success.Resource = api

	return success
}
