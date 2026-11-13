// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/validators"
)

// IntrospectionHandler serves RFC 7662 token introspection for authenticated APIs.
//
// A handler that holds options enforces Endpoints.EnableIntrospectionEndpoint:
// while the switch is off it answers 404 to every request. A handler without
// options does not look at the switch and always serves.
type IntrospectionHandler struct {
	apiValidator     validators.ApiSecretValidator
	requestValidator validators.IntrospectionRequestValidator
	generator        responses.IntrospectionResponseGenerator
	options          *config_options.WicketOptions
	logger           *slog.Logger
}

// NewIntrospectionHandler builds an introspection handler that holds no
// options. It does not enforce Endpoints.EnableIntrospectionEndpoint and serves
// whatever the switch says; use NewIntrospectionHandlerWithOptions for a
// handler that honors the switch.
func NewIntrospectionHandler(
	apiValidator validators.ApiSecretValidator,
	requestValidator validators.IntrospectionRequestValidator,
	generator responses.IntrospectionResponseGenerator,
	logger *slog.Logger,
) *IntrospectionHandler {
	return NewIntrospectionHandlerWithOptions(apiValidator, requestValidator, generator, nil, logger)
}

// NewIntrospectionHandlerWithOptions builds an introspection handler that holds
// options and enforces Endpoints.EnableIntrospectionEndpoint: while the switch
// is off the handler answers 404 to every request. The switch is read on each
// request. Nil options leave the endpoint on.
func NewIntrospectionHandlerWithOptions(
	apiValidator validators.ApiSecretValidator,
	requestValidator validators.IntrospectionRequestValidator,
	generator responses.IntrospectionResponseGenerator,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *IntrospectionHandler {
	return &IntrospectionHandler{
		apiValidator:     apiValidator,
		requestValidator: requestValidator,
		generator:        generator,
		options:          options,
		logger:           logger,
	}
}

func (h *IntrospectionHandler) Process(w http.ResponseWriter, r *http.Request) error {
	// A switched-off endpoint answers as if it did not exist, whatever the
	// request looks like, and before anything of the request is read.
	if h.options != nil && !h.options.Endpoints.EnableIntrospectionEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}
	if r.Method != http.MethodPost {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !extensions.HasApplicationFormContentType(r) {
		return results.NewStatusCodeResult(http.StatusUnsupportedMediaType).Execute(w, r)
	}
	if err := r.ParseForm(); err != nil {
		return results.NewBadRequestResult(wicket.TokenErrorsInvalidRequest, "").Execute(w, r)
	}

	apiResult := h.apiValidator.Validate(r)
	if apiResult == nil || apiResult.Error != nil {
		// RFC 7662 protects the endpoint itself: a caller that cannot
		// authenticate as an API must not learn anything about tokens.
		return results.NewStatusCodeResult(http.StatusUnauthorized).Execute(w, r)
	}

	validationResult, err := h.requestValidator.Validate(r.Context(), r.Form, apiResult.Resource)
	if err != nil {
		return fmt.Errorf("validate introspection request: %w", err)
	}
	if validationResult.Error != nil {
		return results.NewBadRequestResult(validationResult.Error, validationResult.Description).Execute(w, r)
	}

	return results.NewIntrospectionResult(h.generator.Handle(r.Context(), validationResult)).Execute(w, r)
}
