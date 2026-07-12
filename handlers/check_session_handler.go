// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"log/slog"
	"net/http"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
)

// CheckSessionHandler serves the session-management OP iframe document.
type CheckSessionHandler struct {
	options *config_options.WicketOptions
	logger  *slog.Logger
}

func NewCheckSessionHandler(
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *CheckSessionHandler {
	return &CheckSessionHandler{
		options: options,
		logger:  logger,
	}
}

func (h *CheckSessionHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !h.options.Endpoints.EnableCheckSessionEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	return results.NewCheckSessionResult().Execute(w, r)
}
