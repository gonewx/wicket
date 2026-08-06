// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	"github.com/gonewx/wicket/validators/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// DeviceAuthorizationRequestValidator
type DeviceAuthorizationRequestValidator struct {
	Options           *config_options.WicketOptions
	ResourceValidator validators.ResourceValidator
	Logger            *slog.Logger
}

func NewDeviceAuthorizationRequestValidator(
	options *config_options.WicketOptions,
	resourceValidator validators.ResourceValidator,
	logger *slog.Logger,
) *DeviceAuthorizationRequestValidator {
	v := &DeviceAuthorizationRequestValidator{
		Options:           options,
		ResourceValidator: resourceValidator,
		Logger:            logger,
	}
	return v
}

// Validates the request.
func (v *DeviceAuthorizationRequestValidator) ValidateRequest(ctx context.Context, parameters url.Values, clientValidationResult *models.ClientSecretValidationResult) *models.DeviceAuthorizationRequestValidationResult {
	v.Logger.Debug("Start device authorization request validation")

	request := models.NewValidatedDeviceAuthorizationRequest()
	request.Raw = parameters
	request.Options = v.Options

	clientResult := v.validateClient(request, clientValidationResult)
	if clientResult.Error != nil {
		return clientResult
	}

	scopeResult := v.validateScope(ctx, request)
	if scopeResult.Error != nil {
		return scopeResult
	}

	v.Logger.Debug("device authorization request validation success", slog.String("clientId", request.Client.ClientId))

	return v.valid(request)
}

func (v *DeviceAuthorizationRequestValidator) validateClient(request *models.ValidatedDeviceAuthorizationRequest, clientValidationResult *models.ClientSecretValidationResult) *models.DeviceAuthorizationRequestValidationResult {
	// set client & secret
	if clientValidationResult == nil {
		return v.invalid(request, errors.New("argument nil"), "ClientSecretValidationResult")
	}

	request.SetClient(clientValidationResult.Client, clientValidationResult.Secret, "")

	// check if client protocol type is oidc
	if request.Client.ProtocolType != gois.ProtocolTypesOpenIdConnect {
		v.Logger.Error("Invalid protocol type for OIDC authorize endpoint", slog.String("protocolType", request.Client.ProtocolType), slog.Any("request", request))
		return v.invalid(request, gois.AuthorizeErrorsUnauthorizedClient, "Invalid protocol")
	}

	// check if client allows device flow
	if !utils.Contains(request.Client.AllowedGrantTypes(), gois.GrantTypeDeviceCode) {
		v.Logger.Error("Client does not allow device flow", slog.Any("request", request))
		return v.invalid(request, gois.AuthorizeErrorsUnauthorizedClient, "Client does not allow device flow")
	}

	return v.valid(request)
}

func (v *DeviceAuthorizationRequestValidator) validateScope(ctx context.Context, request *models.ValidatedDeviceAuthorizationRequest) *models.DeviceAuthorizationRequestValidationResult {
	// scope must be present
	scope := request.Raw.Get(gois.AuthorizeRequestScope)
	if scope == "" {
		v.Logger.Debug("Client provided no scopes - checking allowed scopes list")

		if len(request.Client.AllowedScopes) > 0 {
			clientAllowedScopes := request.Client.AllowedScopes
			if request.Client.AllowOfflineAccess {
				clientAllowedScopes = append(clientAllowedScopes, gois.StandardScopesOfflineAccess)
			}
			scope = strings.Join(clientAllowedScopes, " ")

			v.Logger.Debug("Defaulting to: ", slog.String("scopes", scope))
		} else {
			v.Logger.Error("No allowed scopes configured for client", slog.Any("request", request))
			return v.invalid(request, gois.AuthorizeErrorsInvalidScope, "")
		}
	}

	if len(scope) > v.Options.InputLengthRestrictions.Scope {
		v.Logger.Error("Scope too long", slog.Any("request", request))
		return v.invalid(request, gois.AuthorizeErrorsInvalidRequest, "Invalid scope")
	}

	request.RequestedScopes = utils.Distinct(strings.Split(scope, " "))

	if utils.Contains(request.RequestedScopes, gois.StandardScopesOpenId) {
		request.IsOpenIdRequest = true
	}

	// check if scopes are valid/supported
	validatedResources, err := v.ResourceValidator.ValidateRequestedResources(
		ctx,
		&validators_models.ResourceValidationRequest{
			Client: request.Client,
			Scopes: request.RequestedScopes,
		},
	)

	if err != nil {
		return v.invalid(request, err, "")
	}

	if !validatedResources.Succeeded() {
		if len(validatedResources.InvalidScopes) > 0 {
			return v.invalid(request, gois.AuthorizeErrorsInvalidScope, "Invalid scope")
		}

		return v.invalid(request, gois.AuthorizeErrorsUnauthorizedClient, "Invalid scope")
	}

	if len(validatedResources.Resources.IdentityResources()) > 0 && !request.IsOpenIdRequest {
		v.Logger.Error("Identity related scope requests, but no openid scope", slog.Any("request", request))
		return v.invalid(request, gois.AuthorizeErrorsInvalidScope, "")
	}

	request.ValidatedResources = validatedResources

	return v.valid(request)
}

func (v *DeviceAuthorizationRequestValidator) valid(request *models.ValidatedDeviceAuthorizationRequest) *models.DeviceAuthorizationRequestValidationResult {
	return models.NewDeviceAuthorizationRequestValidationResult(request)
}

func (v *DeviceAuthorizationRequestValidator) invalid(request *models.ValidatedDeviceAuthorizationRequest, err error, desc string) *models.DeviceAuthorizationRequestValidationResult {
	return models.NewDeviceAuthorizationRequestValidationResult(request,
		models.WithDeviceAuthorizationRequestValidationResultError(err),
		models.WithDeviceAuthorizationRequestValidationResultDescription(desc),
	)
}
