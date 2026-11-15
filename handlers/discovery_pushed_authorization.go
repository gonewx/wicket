// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/utils"
)

// discoveryPushedAuthorization records what the assembly declared about
// pushed authorization requests.
type discoveryPushedAuthorization struct {
	// served is set once pushed authorization requests are enabled.
	served bool
	// required is set when every client has to push its requests.
	required bool
}

// ServePushedAuthorization records that the assembly serves pushed
// authorization requests, and whether every client is required to use them.
// The handler then advertises the pushed authorization request endpoint, see
// settlePushedAuthorizationAdvertisement.
func (h *DiscoveryHandler) ServePushedAuthorization(required bool) {
	h.pushedAuthorization = discoveryPushedAuthorization{served: true, required: required}
}

// settlePushedAuthorizationAdvertisement writes the pushed authorization
// entries of the filtered document. While pushed authorization is not served,
// or its route is not registered, neither entry is advertised, whatever the
// custom entries say. Otherwise the endpoint URL and the requirement flag are
// written, and the mutual TLS alias is added to an advertised aliases entry
// when its route is registered.
func settlePushedAuthorizationAdvertisement(document map[string]any, baseUrl string, options *config_options.WicketOptions, assembly discoveryAssembly, declared discoveryPushedAuthorization) {
	baseUrl = utils.RemoveTrailingSlash(baseUrl)
	endpointPath := utils.EnsureLeadingSlash(wicket.ProtocolRoutePathsPushedAuthorization)
	if !declared.served || !assembly.hasEndpointPath(endpointPath) {
		delete(document, wicket.DiscoveryPushedAuthorizationRequestEndpoint)
		delete(document, wicket.DiscoveryRequirePushedAuthorizationRequests)
		removePushedAuthorizationAlias(document)
		return
	}
	document[wicket.DiscoveryPushedAuthorizationRequestEndpoint] = baseUrl + endpointPath
	document[wicket.DiscoveryRequirePushedAuthorizationRequests] = declared.required

	if !assembly.hasEndpointPath(utils.EnsureLeadingSlash(wicket.ProtocolRoutePathsMtlsPushedAuthorization)) {
		removePushedAuthorizationAlias(document)
		return
	}
	alias := pushedAuthorizationMtlsAlias(baseUrl, options)
	switch aliases := document[wicket.DiscoveryMtlsEndpointAliases].(type) {
	case map[string]string:
		aliases[wicket.DiscoveryPushedAuthorizationRequestEndpoint] = alias
	case map[string]any:
		aliases[wicket.DiscoveryPushedAuthorizationRequestEndpoint] = alias
	}
}

// removePushedAuthorizationAlias drops the pushed authorization entry of the
// mutual TLS aliases, if any.
func removePushedAuthorizationAlias(document map[string]any) {
	switch aliases := document[wicket.DiscoveryMtlsEndpointAliases].(type) {
	case map[string]string:
		delete(aliases, wicket.DiscoveryPushedAuthorizationRequestEndpoint)
	case map[string]any:
		delete(aliases, wicket.DiscoveryPushedAuthorizationRequestEndpoint)
	}
}

// pushedAuthorizationMtlsAlias builds the mutual TLS alias URL of the pushed
// authorization request endpoint the way the other aliases are built: under
// the mtls path prefix of baseUrl, or on the configured mutual TLS domain or
// sub-domain.
func pushedAuthorizationMtlsAlias(baseUrl string, options *config_options.WicketOptions) string {
	route := wicket.ProtocolRoutePathsPushedAuthorization
	domain := ""
	if options != nil && options.MutualTls != nil {
		domain = options.MutualTls.DomainName
	}
	if domain == "" {
		return baseUrl + "/" + strings.Replace(route, wicket.ProtocolRoutePathsConnectPathPrefix, wicket.ProtocolRoutePathsMtlsPathPrefix, 1)
	}
	if strings.Contains(domain, ".") {
		return fmt.Sprintf("https://%s/%s", domain, route)
	}
	_, host, found := strings.Cut(baseUrl, "://")
	if !found {
		host = baseUrl
	}
	return fmt.Sprintf("https://%s.%s/%s", domain, host, route)
}
