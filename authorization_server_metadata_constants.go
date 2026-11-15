// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package wicket

import (
	"fmt"
	"net/url"
	"strings"
)

// OAuth 2.0 authorization server metadata (RFC 8414).
const (
	// ProtocolRoutePathsAuthorizationServerMetadata is the well-known route
	// of the authorization server metadata document (RFC 8414 section 3).
	// When the issuer has a path component, the document is served at this
	// route followed by that path, see AuthorizationServerMetadataPath.
	ProtocolRoutePathsAuthorizationServerMetadata = "/.well-known/oauth-authorization-server"

	// EndpointNamesAuthorizationServerMetadata names the authorization
	// server metadata endpoint.
	EndpointNamesAuthorizationServerMetadata = "AuthorizationServerMetadata"
)

// AuthorizationServerMetadataPath returns the path at which the authorization
// server metadata document of issuer is served: the well-known route with the
// escaped path component of the issuer appended, every trailing slash of that
// path removed (RFC 8414 section 3). An issuer without a path, or with the
// path "/", is served at the bare well-known route. Only the path component
// of issuer is used; its scheme, query and fragment are not checked.
func AuthorizationServerMetadataPath(issuer string) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("parse issuer: %w", err)
	}
	suffix := strings.TrimRight(parsed.EscapedPath(), "/")
	if suffix != "" && !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	return ProtocolRoutePathsAuthorizationServerMetadata + suffix, nil
}
