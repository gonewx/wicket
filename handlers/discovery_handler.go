// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers/results"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/validators"
)

// DiscoveryHandler serves the OpenID Provider configuration document. The
// generated document is filtered against the running assembly: endpoint URLs
// without a registered route, back-channel logout without a delivering
// service, and mutual TLS without a tls client authentication parser are not
// advertised.
type DiscoveryHandler struct {
	generator responses.DiscoveryResponseGenerator
	urls      services.ServerUrls
	issuer    services.IssuerNameService
	options   *config_options.WicketOptions
	assembly  discoveryAssembly
	logger    *slog.Logger
}

// NewDiscoveryHandler builds the discovery handler from the generator and the
// facts of the running assembly: the registered endpoint route paths, the
// back-channel logout service and the secret parsers. A nil endpointPaths
// means no route is registered, so every endpoint URL under the base URL is
// withdrawn from the document; regular use goes through the composition root,
// which supplies the registered routes.
func NewDiscoveryHandler(
	generator responses.DiscoveryResponseGenerator,
	urls services.ServerUrls,
	issuer services.IssuerNameService,
	options *config_options.WicketOptions,
	endpointPaths []string,
	backChannelLogout services.BackchannelLogoutService,
	secretParsers validators.SecretsListParser,
	logger *slog.Logger,
) *DiscoveryHandler {
	assembly := discoveryAssembly{
		endpointPaths:     slices.Clone(endpointPaths),
		backChannelLogout: backChannelLogout,
	}
	if secretParsers != nil {
		assembly.authenticationMethods = secretParsers.GetAvailableAuthenticationMethods()
	}
	return &DiscoveryHandler{
		generator: generator,
		urls:      urls,
		issuer:    issuer,
		options:   options,
		assembly:  assembly,
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

	baseUrl := h.urls.BaseUrl()
	document, err := h.generator.CreateDiscoveryDocument(r.Context(), baseUrl, h.issuer.GetCurrent())
	if err != nil {
		return fmt.Errorf("create discovery document: %w", err)
	}
	filterDiscoveryAdvertisement(document, baseUrl, h.options, h.assembly, h.logger)

	return results.NewDiscoveryDocumentResult(document, h.options.Discovery.ResponseCacheInterval).Execute(w, r)
}

// SetClientAssertionSigningAlgorithms records the signature algorithms of the
// registered private_key_jwt parser. The handler advertises them under
// token_endpoint_auth_signing_alg_values_supported while that method is
// advertised.
func (h *DiscoveryHandler) SetClientAssertionSigningAlgorithms(algorithms []string) {
	h.assembly.clientAssertionSigningAlgorithms = slices.Clone(algorithms)
}
