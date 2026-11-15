// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/handlers/results"
)

// AuthorizationServerMetadataHandler serves the OAuth 2.0 authorization
// server metadata document (RFC 8414). The document is the one the discovery
// handler settles for the OpenID Provider configuration, so both documents
// carry the same keys with the same values. It is served at the well-known
// route followed by the path component of the issuer (RFC 8414 section 3);
// any other path under that route is answered with 404.
type AuthorizationServerMetadataHandler struct {
	discovery *DiscoveryHandler
}

// NewAuthorizationServerMetadataHandler builds the handler on top of the
// discovery handler of the running assembly.
func NewAuthorizationServerMetadataHandler(discovery *DiscoveryHandler) *AuthorizationServerMetadataHandler {
	return &AuthorizationServerMetadataHandler{discovery: discovery}
}

func (h *AuthorizationServerMetadataHandler) Process(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return results.NewStatusCodeResult(http.StatusMethodNotAllowed).Execute(w, r)
	}
	options := h.discovery.options
	if !options.Endpoints.EnableDiscoveryEndpoint {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	document, err := h.discovery.settledDocument(r)
	if err != nil {
		return err
	}
	issuer, ok := document[wicket.DiscoveryIssuer].(string)
	if !ok {
		return fmt.Errorf("authorization server metadata: issuer is not a string: %v", document[wicket.DiscoveryIssuer])
	}
	path, err := wicket.AuthorizationServerMetadataPath(issuer)
	if err != nil {
		return fmt.Errorf("authorization server metadata: %w", err)
	}
	if !matchesAuthorizationServerMetadataPath(r.URL.EscapedPath(), path) {
		return results.NewStatusCodeResult(http.StatusNotFound).Execute(w, r)
	}

	return results.NewDiscoveryDocumentResult(document, options.Discovery.ResponseCacheInterval).Execute(w, r)
}

// matchesAuthorizationServerMetadataPath reports whether the escaped request
// path addresses the served path: the well-known route is compared without
// regard to case, as every endpoint route is, and the issuer path that
// follows it byte for byte.
func matchesAuthorizationServerMetadataPath(requestPath, servedPath string) bool {
	prefix := wicket.ProtocolRoutePathsAuthorizationServerMetadata
	if len(requestPath) < len(prefix) || !strings.EqualFold(requestPath[:len(prefix)], prefix) {
		return false
	}
	return requestPath[len(prefix):] == servedPath[len(prefix):]
}
