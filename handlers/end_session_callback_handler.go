// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/validators"
)

// EndSessionCallbackHandler renders the front-channel logout iframes after logout.
type EndSessionCallbackHandler struct {
	requestValidator validators.EndSessionRequestValidator
	options          *config_options.WicketOptions
	logger           *slog.Logger
}

func NewEndSessionCallbackHandler(
	requestValidator validators.EndSessionRequestValidator,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *EndSessionCallbackHandler {
	return &EndSessionCallbackHandler{
		requestValidator: requestValidator,
		options:          options,
		logger:           logger,
	}
}

func (h *EndSessionCallbackHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !h.options.Endpoints.EnableEndSessionEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	validationResult, err := h.requestValidator.ValidateCallback(r.Context(), r.URL.Query())
	if err != nil {
		return fmt.Errorf("validate end-session callback: %w", err)
	}
	if validationResult.Error != nil {
		return results.NewBadRequestResult(validationResult.Error, validationResult.Description).Execute(w, r)
	}

	return results.NewEndSessionCallbackResult(validationResult).Execute(w, r)
}
