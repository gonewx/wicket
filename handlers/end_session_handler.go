// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/validators"
)

// EndSessionHandler serves RP-initiated logout requests.
type EndSessionHandler struct {
	requestValidator validators.EndSessionRequestValidator
	session          services.UserSession
	options          *config_options.WicketOptions
	logger           *slog.Logger
}

func NewEndSessionHandler(
	requestValidator validators.EndSessionRequestValidator,
	session services.UserSession,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *EndSessionHandler {
	return &EndSessionHandler{
		requestValidator: requestValidator,
		session:          session,
		options:          options,
		logger:           logger,
	}
}

func (h *EndSessionHandler) Process(w http.ResponseWriter, r *http.Request) error {
	var parameters url.Values
	switch r.Method {
	case http.MethodGet:
		parameters = r.URL.Query()
	case http.MethodPost:
		if !extensions.HasApplicationFormContentType(r) {
			return results.NewStatusCodeResult(http.StatusUnsupportedMediaType).Execute(w, r)
		}
		if err := r.ParseForm(); err != nil {
			return results.NewStatusCodeResult(http.StatusBadRequest).Execute(w, r)
		}
		parameters = r.PostForm
	default:
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !h.options.Endpoints.EnableEndSessionEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	validationResult, err := h.requestValidator.Validate(parameters, h.session.GetUser())
	if err != nil {
		return fmt.Errorf("validate end-session request: %w", err)
	}

	// Both the valid and the invalid request land on the logout page; an
	// invalid request simply carries no logout message (result behavior).
	return results.NewEndSessionResult(validationResult).Execute(w, r)
}
