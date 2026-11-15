// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/services"
)

// introspectionSigning holds what a handler needs to answer with signed
// introspection responses (RFC 9701).
type introspectionSigning struct {
	keys   services.KeyMaterialService
	issuer services.IssuerNameService
	clock  services.SystemClock
}

// ServeSignedResponses lets the handler answer a resource server that asks
// for application/token-introspection+jwt with a signed JWT (RFC 9701). The
// signing credential comes from the key material service, chosen by its
// regular selection rules; the issuer and the issued-at time come from the
// given services. A handler on which this was never called answers every
// request with JSON.
func (h *IntrospectionHandler) ServeSignedResponses(keys services.KeyMaterialService, issuer services.IssuerNameService, clock services.SystemClock) {
	if keys == nil || issuer == nil || clock == nil {
		h.signing = nil
		return
	}
	h.signing = &introspectionSigning{keys: keys, issuer: issuer, clock: clock}
}

// acceptsIntrospectionJwt reports whether the Accept header values name
// application/token-introspection+jwt explicitly with a non-zero quality.
// Wildcard ranges such as */* or application/* do not count.
func acceptsIntrospectionJwt(accept []string) bool {
	for _, header := range accept {
		for _, mediaRange := range strings.Split(header, ",") {
			if acceptsMediaRange(mediaRange, wicket.MediaTypesTokenIntrospectionJwt) {
				return true
			}
		}
	}
	return false
}

func acceptsMediaRange(mediaRange string, mediaType string) bool {
	name, parameters, _ := strings.Cut(mediaRange, ";")
	if !strings.EqualFold(strings.TrimSpace(name), mediaType) {
		return false
	}
	for _, parameter := range strings.Split(parameters, ";") {
		key, value, ok := strings.Cut(parameter, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "q") {
			continue
		}
		// An unreadable quality is not an explicit request for the type.
		quality, err := strconv.ParseFloat(strings.Trim(strings.TrimSpace(value), `"`), 64)
		return err == nil && quality > 0
	}
	return true
}

// sign builds and signs the introspection response JWT. The payload carries
// exactly iss, aud, iat and token_introspection, the latter being the
// introspection result unchanged; the header carries the credential's alg,
// its kid when it has one, and typ token-introspection+jwt.
func (s *introspectionSigning) sign(ctx context.Context, audience string, introspection map[string]any) (string, error) {
	credential, err := s.keys.GetSigningCredentials(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("sign introspection response: select signing credential: %w", err)
	}
	if credential == nil || credential.Key == nil {
		return "", errors.New("sign introspection response: no signing credential available")
	}
	alg, ok := jwa.LookupSignatureAlgorithm(credential.Algorithm)
	if !ok {
		return "", fmt.Errorf("sign introspection response: unknown algorithm %q", credential.Algorithm)
	}

	if introspection == nil {
		introspection = map[string]any{}
	}
	payload, err := json.Marshal(map[string]any{
		wicket.JwtClaimTypesIssuer:          s.issuer.GetCurrent(),
		wicket.JwtClaimTypesAudience:        audience,
		wicket.JwtClaimTypesIssuedAt:        s.clock.Now().Unix(),
		wicket.ClaimTypesTokenIntrospection: introspection,
	})
	if err != nil {
		return "", fmt.Errorf("sign introspection response: build payload: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, wicket.JwtTypesTokenIntrospection); err != nil {
		return "", fmt.Errorf("sign introspection response: set typ header: %w", err)
	}
	if credential.Kid != "" {
		if err := headers.Set(jws.KeyIDKey, credential.Kid); err != nil {
			return "", fmt.Errorf("sign introspection response: set kid header: %w", err)
		}
	}

	signed, err := jws.Sign(payload, jws.WithKey(alg, credential.Key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("sign introspection response: sign: %w", err)
	}
	return string(signed), nil
}
