// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"fmt"
	"log/slog"
	"strings"

	config_options "github.com/gonewx/wicket/config/options"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// DeviceAuthorizationResponseGenerator The device authorization response generator
type DeviceAuthorizationResponseGenerator struct {
	options               *config_options.IdentityServerOptions
	userCodeService       services.UserCodeService
	deviceFlowCodeService services.DeviceFlowCodeService
	clock                 services.SystemClock
	logger                *slog.Logger
}

func NewDeviceAuthorizationResponseGenerator(
	options *config_options.IdentityServerOptions,
	userCodeService services.UserCodeService,
	deviceFlowCodeService services.DeviceFlowCodeService,
	clock services.SystemClock,
	logger *slog.Logger,
) *DeviceAuthorizationResponseGenerator {
	return &DeviceAuthorizationResponseGenerator{
		options:               options,
		userCodeService:       userCodeService,
		deviceFlowCodeService: deviceFlowCodeService,
		clock:                 clock,
		logger:                logger,
	}
}

// Processes the response.
func (g *DeviceAuthorizationResponseGenerator) Handle(validationResult *validators_models.DeviceAuthorizationRequestValidationResult, baseUrl string) (*responses_models.DeviceAuthorizationResponse, error) {
	if validationResult == nil {
		return nil, fmt.Errorf("validationResult is nil")
	}
	if validationResult.ValidatedRequest.Client == nil {
		return nil, fmt.Errorf("validatedRequest.Client is nil")
	}
	if strings.TrimSpace(baseUrl) == "" {
		return nil, fmt.Errorf("baseUrl is empty")
	}

	g.logger.Debug("Creating response for device authorization request")

	response := &responses_models.DeviceAuthorizationResponse{}

	userCodeType := g.options.DeviceFlow.DefaultUserCodeType

	if validationResult.ValidatedRequest.Client.UserCodeType != "" {
		userCodeType = validationResult.ValidatedRequest.Client.UserCodeType
	}
	// generate user_code
	userCodeGenerator := g.userCodeService.GetGenerator(userCodeType)

	retryCount := 0

	for {
		userCode := userCodeGenerator.Generate()

		deviceCode, err := g.deviceFlowCodeService.FindByUserCode(userCode)
		if err != nil || deviceCode == nil {
			response.UserCode = userCode
			break
		}

		retryCount++
		if retryCount >= userCodeGenerator.GetRetryLimit() {
			break
		}
	}

	if response.UserCode == "" {
		return nil, fmt.Errorf("Unable to create unique device flow user code")
	}

	// generate verification URIs
	response.VerificationUri = g.options.UserInteraction.DeviceVerificationUrl
	if utils.IsLocalUrl(response.VerificationUri) {
		// if url is relative, parse absolute URL
		response.VerificationUri = utils.RemoveTrailingSlash(baseUrl) + g.options.UserInteraction.DeviceVerificationUrl
	}

	if strings.TrimSpace(g.options.UserInteraction.DeviceVerificationUserCodeParameter) != "" {
		response.VerificationUriComplete = fmt.Sprintf("%s?%s=%s", response.VerificationUri, g.options.UserInteraction.DeviceVerificationUserCodeParameter, response.UserCode)
	}

	// expiration
	response.DeviceCodeLifetime = validationResult.ValidatedRequest.Client.DeviceCodeLifetime

	// interval
	response.Interval = g.options.DeviceFlow.Interval

	// store device request (device code & user code)
	var err error
	response.DeviceCode, err = g.deviceFlowCodeService.StoreDeviceAuthorization(response.UserCode, &storage_models.DeviceCode{
		Description:     validationResult.ValidatedRequest.Client.Description,
		ClientId:        validationResult.ValidatedRequest.Client.ClientId,
		IsOpenId:        validationResult.ValidatedRequest.IsOpenIdRequest,
		Lifetime:        response.DeviceCodeLifetime,
		CreationTime:    g.clock.Now(),
		RequestedScopes: validationResult.ValidatedRequest.ValidatedResources.RawScopeValues(),
	})

	if err != nil {
		return nil, err
	}

	return response, nil
}
