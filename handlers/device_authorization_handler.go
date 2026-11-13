// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/validators"
)

// deviceAuthorizationProtocolErrors are the request validator errors answered
// to the client as 400; any other validator error is an internal failure.
var deviceAuthorizationProtocolErrors = []error{
	wicket.AuthorizeErrorsInvalidRequest,
	wicket.AuthorizeErrorsInvalidScope,
	wicket.AuthorizeErrorsUnauthorizedClient,
}

// DeviceAuthorizationHandler serves the RFC 8628 device authorization
// endpoint: an authenticated client asks for a device code and a user code.
type DeviceAuthorizationHandler struct {
	clientValidator  validators.ClientSecretValidator
	requestValidator validators.DeviceAuthorizationRequestValidator
	generator        responses.DeviceAuthorizationResponseGenerator
	urls             services.ServerUrls
	options          *config_options.WicketOptions
	logger           *slog.Logger
}

func NewDeviceAuthorizationHandler(
	clientValidator validators.ClientSecretValidator,
	requestValidator validators.DeviceAuthorizationRequestValidator,
	generator responses.DeviceAuthorizationResponseGenerator,
	urls services.ServerUrls,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *DeviceAuthorizationHandler {
	return &DeviceAuthorizationHandler{
		clientValidator:  clientValidator,
		requestValidator: requestValidator,
		generator:        generator,
		urls:             urls,
		options:          options,
		logger:           logger,
	}
}

func (h *DeviceAuthorizationHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if !h.options.Endpoints.EnableDeviceAuthorizationEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}
	if r.Method != http.MethodPost {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !extensions.HasApplicationFormContentType(r) {
		return results.NewStatusCodeResult(http.StatusUnsupportedMediaType).Execute(w, r)
	}
	if err := r.ParseForm(); err != nil {
		return results.NewDeviceAuthorizationErrorResult(wicket.AuthorizeErrorsInvalidRequest).Execute(w, r)
	}

	// RFC 8628 §3.1: clients with credentials authenticate as at the token
	// endpoint; a public client identifies itself with client_id alone.
	clientResult := h.clientValidator.Validate(r)
	if clientResult == nil || clientResult.Error != nil || clientResult.Client == nil {
		h.debug("device authorization client authentication failed")
		challenge := authorizationChallenge(r)
		return results.NewClientAuthenticationErrorResult(challenge).Execute(w, r)
	}
	clientId := clientResult.Client.ClientId

	// The parameters are read from the request body only.
	validation := h.requestValidator.ValidateRequest(r.Context(), r.PostForm, clientResult)
	if validation == nil {
		return errors.New("validate device authorization request: no result")
	}
	if validation.Error != nil {
		for _, protocolError := range deviceAuthorizationProtocolErrors {
			if errors.Is(validation.Error, protocolError) {
				h.debug("device authorization request rejected",
					slog.String("clientId", clientId),
					slog.String("error", protocolError.Error()),
				)
				return results.NewDeviceAuthorizationErrorResult(protocolError).Execute(w, r)
			}
		}
		return fmt.Errorf("validate device authorization request: %w", validation.Error)
	}

	response, err := h.generator.Handle(r.Context(), validation, h.urls.BaseUrl())
	if err != nil {
		return fmt.Errorf("create device authorization: %w", err)
	}

	h.debug("device authorization issued", slog.String("clientId", clientId))
	return results.NewDeviceAuthorizationResult(response).Execute(w, r)
}

func (h *DeviceAuthorizationHandler) debug(msg string, args ...any) {
	if h.logger != nil {
		h.logger.Debug(msg, args...)
	}
}
