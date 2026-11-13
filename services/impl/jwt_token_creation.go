// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// TokenCreationService serializes a token model into a signed JWS compact
// string. The payload is assembled from the model's fields and claims; the JOSE
// header advertises the algorithm and key id of the selected signing credential
// plus the token-type media type. Signing material is chosen through the
// injected key material service, so the header key id resolves through the
// published JWKS on the validation side.
type TokenCreationService struct {
	keys    services.KeyMaterialService
	clock   services.SystemClock
	options *config_options.WicketOptions
	logger  *slog.Logger
}

func NewTokenCreationService(
	keys services.KeyMaterialService,
	clock services.SystemClock,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) *TokenCreationService {
	return &TokenCreationService{keys: keys, clock: clock, options: options, logger: logger}
}

// CreateToken builds and signs the JWS for the token. It fails closed: a missing
// signing credential or any serialization/signing error yields an error rather
// than an unsigned or partial string.
func (s *TokenCreationService) CreateToken(ctx context.Context, token *storage_models.Token) (string, error) {
	credential, err := s.keys.GetSigningCredentials(ctx, token.AllowedSigningAlgorithms)
	if err != nil {
		return "", fmt.Errorf("create token: select signing credential: %w", err)
	}
	if credential == nil || credential.Key == nil {
		return "", fmt.Errorf("create token: no signing credential available")
	}

	payload, err := extensions.CreateJwtPayload(token, s.options, s.clock, s.logger)
	if err != nil {
		return "", fmt.Errorf("create token: build payload: %w", err)
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, s.headerType(token)); err != nil {
		return "", fmt.Errorf("create token: set typ header: %w", err)
	}
	if credential.Kid != "" {
		if err := headers.Set(jws.KeyIDKey, credential.Kid); err != nil {
			return "", fmt.Errorf("create token: set kid header: %w", err)
		}
	}

	alg, ok := jwa.LookupSignatureAlgorithm(credential.Algorithm)
	if !ok {
		return "", fmt.Errorf("create token: unknown algorithm %q", credential.Algorithm)
	}

	signed, err := jwt.Sign(payload, jwt.WithKey(
		alg,
		credential.Key,
		jws.WithProtectedHeaders(headers),
	))
	if err != nil {
		return "", fmt.Errorf("create token: sign jwt: %w", err)
	}
	return string(signed), nil
}

// headerType selects the JOSE typ header. Access tokens carry the configured
// access-token media type (RFC 9068, default "at+jwt") so the resource
// validation path can distinguish them from other JWTs; every other token uses
// the RFC 7519 default, except logout tokens, which are explicitly typed
// "logout+jwt" (OIDC Back-Channel Logout 1.0 §2.4, §4.1) so they cannot be
// mistaken for any other JWT the provider issues.
func (s *TokenCreationService) headerType(token *storage_models.Token) string {
	if token.Type == wicket.TokenTypesAccessToken && s.options.AccessTokenJwtType != "" {
		return s.options.AccessTokenJwtType
	}
	if token.Type == TokenTypesLogoutToken {
		return LogoutTokenJwtType
	}
	return "JWT"
}
