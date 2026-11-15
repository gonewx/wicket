// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting

import (
	"net/http"
	"strings"

	"github.com/gonewx/wicket"
)

// findAuthorizationServerMetadataHandler looks up the handler of a request
// addressing the authorization server metadata route followed by an issuer
// path (RFC 8414 section 3). The route is registered without the issuer path,
// which is only known per request, so such a request is looked up under the
// bare route; the handler then judges the full path against the issuer. A
// request outside that route yields no handler.
func findAuthorizationServerMetadataHandler(router EndpointRouter, r *http.Request) (EndpointHandler, error) {
	prefix := wicket.ProtocolRoutePathsAuthorizationServerMetadata + "/"
	if len(r.URL.Path) < len(prefix) || !strings.EqualFold(r.URL.Path[:len(prefix)], prefix) {
		return nil, nil
	}
	bareUrl := *r.URL
	bareUrl.Path = wicket.ProtocolRoutePathsAuthorizationServerMetadata
	bareUrl.RawPath = ""
	bare := new(http.Request)
	*bare = *r
	bare.URL = &bareUrl
	return router.Find(bare)
}
