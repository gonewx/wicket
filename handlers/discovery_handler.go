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

	// servesClientCertificateAuthentication is set once the assembly
	// declared mutual TLS client authentication enabled.
	servesClientCertificateAuthentication bool

	// pushedAuthorization is what the assembly declared about pushed
	// authorization requests, see ServePushedAuthorization.
	pushedAuthorization discoveryPushedAuthorization

	// servesDPoP is set once the assembly declared DPoP enabled, and
	// dpopSigningAlgorithms holds the proof signature algorithms it accepts.
	servesDPoP            bool
	dpopSigningAlgorithms []string

	// introspectionSigningKeys is set once the assembly declared signed
	// introspection responses, see ServeSignedIntrospection.
	introspectionSigningKeys services.KeyMaterialService

	// servesAccountCreation is set once the assembly declared an account
	// creation page for the create prompt, see ServeAccountCreation.
	servesAccountCreation bool
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

	document, err := h.settledDocument(r)
	if err != nil {
		return err
	}

	return results.NewDiscoveryDocumentResult(document, h.options.Discovery.ResponseCacheInterval).Execute(w, r)
}

// settledDocument generates the discovery document for the request and
// filters and settles it against the running assembly. It is the single
// source of both the OpenID Provider configuration and the authorization
// server metadata document.
func (h *DiscoveryHandler) settledDocument(r *http.Request) (map[string]any, error) {
	baseUrl := h.urls.BaseUrl()
	document, err := h.generator.CreateDiscoveryDocument(r.Context(), baseUrl, h.issuer.GetCurrent())
	if err != nil {
		return nil, fmt.Errorf("create discovery document: %w", err)
	}
	filterDiscoveryAdvertisement(document, baseUrl, h.options, h.assembly, h.logger)
	if h.servesClientCertificateAuthentication {
		settleMutualTlsAdvertisement(document, h.options)
	}
	settlePushedAuthorizationAdvertisement(document, baseUrl, h.options, h.assembly, h.pushedAuthorization)
	settleDPoPAdvertisement(document, h.servesDPoP, h.dpopSigningAlgorithms, h.logger)
	settlePromptValuesAdvertisement(document, h.servesAccountCreation, h.logger)
	if err := settleIntrospectionSigningAdvertisement(r.Context(), document, baseUrl, h.introspectionSigningKeys, h.logger); err != nil {
		return nil, fmt.Errorf("settle discovery document: %w", err)
	}
	return document, nil
}

// SetClientAssertionSigningAlgorithms records the signature algorithms of the
// registered private_key_jwt parser. The handler advertises them under
// token_endpoint_auth_signing_alg_values_supported while that method is
// advertised.
func (h *DiscoveryHandler) SetClientAssertionSigningAlgorithms(algorithms []string) {
	h.assembly.clientAssertionSigningAlgorithms = slices.Clone(algorithms)
}

// ServeClientCertificateAuthentication records that the assembly serves
// mutual TLS client authentication. The handler then settles the mutual TLS
// entries of the filtered document, see settleMutualTlsAdvertisement.
func (h *DiscoveryHandler) ServeClientCertificateAuthentication() {
	h.servesClientCertificateAuthentication = true
}

// ServeAsymmetricRequestObjectsOnly records that the assembly accepts only
// asymmetrically signed request objects. The handler then advertises only
// those algorithms under request_object_signing_alg_values_supported.
func (h *DiscoveryHandler) ServeAsymmetricRequestObjectsOnly() {
	h.assembly.asymmetricRequestObjectsOnly = true
}
