// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/validators"
)

// IntrospectionHandler serves RFC 7662 token introspection for authenticated APIs.
type IntrospectionHandler struct {
	apiValidator     validators.ApiSecretValidator
	requestValidator validators.IntrospectionRequestValidator
	generator        responses.IntrospectionResponseGenerator
	logger           *slog.Logger
}

func NewIntrospectionHandler(
	apiValidator validators.ApiSecretValidator,
	requestValidator validators.IntrospectionRequestValidator,
	generator responses.IntrospectionResponseGenerator,
	logger *slog.Logger,
) *IntrospectionHandler {
	return &IntrospectionHandler{
		apiValidator:     apiValidator,
		requestValidator: requestValidator,
		generator:        generator,
		logger:           logger,
	}
}

func (h *IntrospectionHandler) Process(w http.ResponseWriter, r *http.Request) error {
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
