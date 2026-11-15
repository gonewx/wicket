// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/utils"
)

// ServeSignedIntrospection records that the introspection endpoint of the
// assembly answers with signed responses (RFC 9701) signed by the given key
// material. The handler then advertises the signing algorithms under
// introspection_signing_alg_values_supported, see
// settleIntrospectionSigningAdvertisement.
func (h *DiscoveryHandler) ServeSignedIntrospection(keys services.KeyMaterialService) {
	h.introspectionSigningKeys = keys
}

// settleIntrospectionSigningAdvertisement writes
// introspection_signing_alg_values_supported. The key is written only here: a
// value already in the document, which can only come from the host's custom
// entries, is dropped with a warning. The algorithms of all signing
// credentials, without duplicates and in first-seen order, are written when
// signed introspection responses are served, the settled document advertises
// the introspection endpoint of this server, and at least one credential
// exists.
func settleIntrospectionSigningAdvertisement(
	ctx context.Context,
	document map[string]any,
	baseUrl string,
	keys services.KeyMaterialService,
	logger *slog.Logger,
) error {
	key := wicket.DiscoveryIntrospectionSigningAlgValuesSupported
	if _, ok := document[key]; ok {
		delete(document, key)
		if logger != nil {
			logger.Warn("A custom discovery entry named introspection_signing_alg_values_supported is ignored; the key is written only from the signed introspection declaration.")
		}
	}
	if keys == nil || !advertisesLocalIntrospectionEndpoint(document, baseUrl) {
		return nil
	}

	credentials, err := keys.GetAllSigningCredentials(ctx)
	if err != nil {
		return fmt.Errorf("list signing credentials: %w", err)
	}
	algorithms := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		if credential == nil || credential.Algorithm == "" || slices.Contains(algorithms, credential.Algorithm) {
			continue
		}
		algorithms = append(algorithms, credential.Algorithm)
	}
	if len(algorithms) > 0 {
		document[key] = algorithms
	}
	return nil
}

// advertisesLocalIntrospectionEndpoint reports whether the document's
// introspection_endpoint is the introspection route of this server.
func advertisesLocalIntrospectionEndpoint(document map[string]any, baseUrl string) bool {
	raw, ok := document[wicket.DiscoveryIntrospectionEndpoint].(string)
	if !ok {
		return false
	}
	filter := &discoveryFilter{baseUrl: utils.RemoveTrailingSlash(baseUrl)}
	path, local := filter.localPath(raw)
	return local && strings.EqualFold(path, utils.EnsureLeadingSlash(wicket.ProtocolRoutePathsIntrospection))
}
