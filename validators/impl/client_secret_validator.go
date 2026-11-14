// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/extensions"
	storage "github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/validators"
	"github.com/gonewx/wicket/validators/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// ClientSecretValidator for handling client authentication
type ClientSecretValidator struct {
	logger    *slog.Logger
	clients   storage.ClientStore
	validator validators.SecretsListValidator
	parser    validators.SecretsListParser
}

func NewClientSecretValidator(
	logger *slog.Logger,
	clients storage.ClientStore,
	validator validators.SecretsListValidator,
	parser validators.SecretsListParser,
) *ClientSecretValidator {
	return &ClientSecretValidator{
		logger:    logger,
		clients:   clients,
		validator: validator,
		parser:    parser,
	}
}

// Tries to authenticate a client based on the incoming request
func (v *ClientSecretValidator) Validate(req *http.Request) *models.ClientSecretValidationResult {
	v.logger.Debug("Start client validation")

	fail := validators_models.NewClientSecretValidationResult()
	fail.Error = wicket.TokenErrorsInvalidClient

	parsedSecret, err := v.parser.Parse(req)
	if err != nil || parsedSecret == nil {
		v.logger.Error("No client identifier found")

		fail.Error = wicket.TokenErrorsInvalidRequest
		return fail
	}

	// load client
	client, err := extensions.FindEnabledClientById(req.Context(), v.clients, parsedSecret.Id)
	if err != nil && !extensions.IsClientRejected(err) {
		v.logger.Error("Client store failed while loading client", slog.String("clientId", parsedSecret.Id), slog.String("error", err.Error()))
		fail.Error = fmt.Errorf("%w: %w", clientassertion.ErrAuthenticationUnavailable, err)
		return fail
	}
	if err != nil || client == nil {
		v.logger.Error("No client with id '{clientId}' found. aborting", slog.String("clientId", parsedSecret.Id))
		return fail
	}

	confirmation := ""
	if !client.RequireClientSecret || client.IsImplicitOnly() {
		v.logger.Debug("Public Client - skipping secret validation success")
	} else {
		secretValidationResult, err := v.validator.Validate(client.ClientSecrets, parsedSecret)
		if err != nil || secretValidationResult == nil || !secretValidationResult.Success {
			v.logger.Error("Client secret validation failed for client", slog.String("clientId", client.ClientId))

			return fail
		}
		confirmation = secretValidationResult.Confirmation
	}

	v.logger.Debug("Client validation success")

	success := validators_models.NewClientSecretValidationResult()
	success.Client = client
	success.Secret = parsedSecret
	success.Confirmation = confirmation

	return success
}
