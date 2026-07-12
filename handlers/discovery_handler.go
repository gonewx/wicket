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
	"github.com/gonewx/wicket/services"
)

// DiscoveryHandler serves the OpenID Provider configuration document.
type DiscoveryHandler struct {
	generator responses.DiscoveryResponseGenerator
	urls      services.ServerUrls
	issuer    services.IssuerNameService
	options   *config_options.WicketOptions
	logger    *slog.Logger
}

func NewDiscoveryHandler(
	generator responses.DiscoveryResponseGenerator,
	urls services.ServerUrls,
	issuer services.IssuerNameService,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *DiscoveryHandler {
	return &DiscoveryHandler{
		generator: generator,
		urls:      urls,
		issuer:    issuer,
		options:   options,
		logger:    logger,
	}
}

func (h *DiscoveryHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	if !h.options.Endpoints.EnableDiscoveryEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	document, err := h.generator.CreateDiscoveryDocument(h.urls.BaseUrl(), h.issuer.GetCurrent())
	if err != nil {
		return fmt.Errorf("create discovery document: %w", err)
	}

	return results.NewDiscoveryDocumentResult(document, h.options.Discovery.ResponseCacheInterval).Execute(w, r)
}
