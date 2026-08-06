// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"log/slog"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/extensions"
	models_contexts "github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// DeviceCodeValidator Allows inserting custom validation logic into token requests
type DeviceCodeValidator struct {
	devices           services.DeviceFlowCodeService
	profile           services.ProfileService
	throttlingService services.DeviceFlowThrottlingService
	systemClock       services.SystemClock
	logger            *slog.Logger
}

func NewDeviceCodeValidator(
	devices services.DeviceFlowCodeService,
	profile services.ProfileService,
	throttlingService services.DeviceFlowThrottlingService,
	systemClock services.SystemClock,
	logger *slog.Logger,
) *DeviceCodeValidator {
	v := &DeviceCodeValidator{
		devices:           devices,
		profile:           profile,
		throttlingService: throttlingService,
		systemClock:       systemClock,
		logger:            logger,
	}
	return v
}

// Custom validation logic for a token request.
func (v *DeviceCodeValidator) Validate(ctx context.Context, validation *validators_models.DeviceCodeValidationContext) error {
	deviceCode, err := v.devices.FindByDeviceCode(ctx, validation.DeviceCode)
	if err != nil || deviceCode == nil {
		v.logger.Error("Invalid device code")
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsInvalidGrant),
		)
		return nil
	}

	// validate client binding
	if deviceCode.ClientId != validation.Request.Client.ClientId {
		v.logger.Error("Client 0 is trying to use a device code from client 1", slog.String("client0", validation.Request.Client.ClientId), slog.String("client1", deviceCode.ClientId))
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsInvalidGrant),
		)
		return nil
	}

	shouldSlowDown, err := v.throttlingService.ShouldSlowDown(ctx, validation.DeviceCode, deviceCode)

	if err != nil || shouldSlowDown {
		v.logger.Error("Client is polling too fast", slog.String("client", deviceCode.ClientId))
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsSlowDown),
		)
		return nil
	}

	// validate lifetime
	if deviceCode.CreationTime.Add(time.Duration(deviceCode.Lifetime) * time.Second).Before(v.systemClock.Now()) {
		v.logger.Error("Expired device code")
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsExpiredToken),
		)
		return nil
	}

	// denied
	if deviceCode.IsAuthorized && len(deviceCode.AuthorizedScopes) == 0 {
		v.logger.Error("No scopes authorized for device authorization. Access denied")
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsAccessDenied),
		)
		return nil
	}

	// make sure code is authorized
	if !deviceCode.IsAuthorized || deviceCode.Subject == nil {
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsAuthorizationPending),
		)
		return nil
	}

	// make sure user is enabled
	isActiveCtx := models_contexts.NewIsActiveContext(deviceCode.Subject, validation.Request.Client, gois.ProfileIsActiveCallersDeviceCodeValidation)

	v.profile.IsActive(isActiveCtx)
	if !isActiveCtx.IsActive {
		v.logger.Error("User has been disabled:", slog.String("subjectId", extensions.GetSubjectIdFromPrincipal(deviceCode.Subject)))
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsInvalidGrant),
		)
		return nil
	}

	validation.Request.DeviceCode = deviceCode
	validation.Request.SessionId = deviceCode.SessionId

	validation.Result = validators_models.NewTokenRequestValidationResult(validation.Request)
	err = v.devices.RemoveByDeviceCode(ctx, validation.DeviceCode)
	if err != nil {
		v.logger.Error("Error removing device code", slog.String("err", err.Error()))
		validation.Result = validators_models.NewTokenRequestValidationResult(
			validation.Request,
			validators_models.WithTokenRequestValidationResultError(gois.TokenErrorsInvalidGrant),
		)
		return nil
	}
	return nil
}
