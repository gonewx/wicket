// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
)

// DiscoveryKeyHandler serves the JSON Web Key Set document.
type DiscoveryKeyHandler struct {
	generator responses.DiscoveryResponseGenerator
	options   *config_options.WicketOptions
	logger    *slog.Logger
}

func NewDiscoveryKeyHandler(
	generator responses.DiscoveryResponseGenerator,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *DiscoveryKeyHandler {
	return &DiscoveryKeyHandler{
		generator: generator,
		options:   options,
		logger:    logger,
	}
}

func (h *DiscoveryKeyHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !h.options.Endpoints.EnableDiscoveryEndpoint || !h.options.Discovery.ShowKeySet {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	keys, err := h.generator.CreateJwkDocument(r.Context())
	if err != nil {
		return fmt.Errorf("create jwk document: %w", err)
	}

	return results.NewJsonWebKeysResult(keys, h.options.Discovery.ResponseCacheInterval).Execute(w, r)
}
