// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package results

import (
	"net/http"

	"github.com/gonewx/wicket"
)

// IntrospectionJwtResult writes a signed introspection response (RFC 9701):
// status 200, the caching headers of the JSON introspection response, the
// application/token-introspection+jwt content type and the compact JWT as
// the body, without a trailing newline.
type IntrospectionJwtResult struct {
	Jwt string
}

func NewIntrospectionJwtResult(jwt string) *IntrospectionJwtResult {
	return &IntrospectionJwtResult{Jwt: jwt}
}

func (r *IntrospectionJwtResult) Execute(w http.ResponseWriter, _ *http.Request) error {
	HttpRespSetNoCache(w)
	w.Header().Set("Content-Type", wicket.MediaTypesTokenIntrospectionJwt)
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(r.Jwt))
	return err
}
