// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"errors"
	"log/slog"

	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/storage"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// TokenRevocationResponseGenerator Default revocation response generator
type TokenRevocationResponseGenerator struct {
	referenceTokenStore storage.ReferenceTokenStore
	refreshTokenStore   storage.RefreshTokenStore
	logger              *slog.Logger
}

func NewTokenRevocationResponseGenerator(
	referenceTokenStore storage.ReferenceTokenStore,
	refreshTokenStore storage.RefreshTokenStore,
	logger *slog.Logger,
) *TokenRevocationResponseGenerator {
	return &TokenRevocationResponseGenerator{
		referenceTokenStore: referenceTokenStore,
		refreshTokenStore:   refreshTokenStore,
		logger:              logger,
	}
}

// Handle Creates the revocation endpoint response and processes the revocation request.
func (g *TokenRevocationResponseGenerator) Handle(ctx context.Context, validationResult *validators_models.TokenRevocationRequestValidationResult) (*responses_models.TokenRevocationResponse, error) {
	response := &responses_models.TokenRevocationResponse{
		Success:   true,
		TokenType: validationResult.TokenTypeHint,
	}

	var err error
	// revoke tokens
	if validationResult.TokenTypeHint == gois.TokenTypeHintsAccessToken {
		g.logger.Debug("Hint was for access token")
		response.Success, err = g.revokeAccessToken(ctx, validationResult)
		if err != nil {
			return nil, err
		}
	} else {
		if validationResult.TokenTypeHint == gois.TokenTypeHintsRefreshToken {
			g.logger.Debug("Hint was for refresh token")

			response.Success, err = g.revokeRefreshToken(ctx, validationResult)
			if err != nil {
				return nil, err
			}
		} else {
			g.logger.Debug("No hint for token type")
			response.Success, err = g.revokeAccessToken(ctx, validationResult)
			if err != nil {
				return nil, err
			}

			if !response.Success {
				response.Success, err = g.revokeRefreshToken(ctx, validationResult)
				if err != nil {
					return nil, err
				}
				response.TokenType = gois.TokenTypeHintsRefreshToken
			} else {
				response.TokenType = gois.TokenTypeHintsAccessToken
			}
		}
	}

	return response, nil
}

func (g *TokenRevocationResponseGenerator) revokeAccessToken(ctx context.Context, validationResult *validators_models.TokenRevocationRequestValidationResult) (bool, error) {
	token, err := g.referenceTokenStore.GetReferenceToken(ctx, validationResult.Token)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Nothing to revoke: RFC 7009 revocations are idempotent.
			return true, nil
		}
		return false, err
	}
	if token == nil {
		return true, nil
	}

	if token.ClientId == validationResult.Client.ClientId {
		g.logger.Debug("Access token revoked")
		if err := g.referenceTokenStore.RemoveReferenceToken(ctx, validationResult.Token); err != nil {
			return false, err
		}
	} else {
		g.logger.Debug("Client denied from revoking access token belonging to Client", slog.String("clientId", validationResult.Client.ClientId), slog.String("tokenClientId", token.ClientId))
	}

	return true, nil
}

// revokeRefreshToken Revoke refresh token only if it belongs to client doing the request
func (g *TokenRevocationResponseGenerator) revokeRefreshToken(ctx context.Context, validationResult *validators_models.TokenRevocationRequestValidationResult) (bool, error) {
	token, err := g.refreshTokenStore.GetRefreshToken(ctx, validationResult.Token)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Nothing to revoke: RFC 7009 revocations are idempotent.
			return true, nil
		}
		return false, err
	}
	if token == nil {
		return true, nil
	}

	if token.ClientId == validationResult.Client.ClientId {
		g.logger.Debug("Refresh token revoked")
		if err := g.refreshTokenStore.RemoveRefreshToken(ctx, validationResult.Token); err != nil {
			return false, err
		}
		if err := g.referenceTokenStore.RemoveReferenceTokens(ctx, token.SubjectId(), token.ClientId); err != nil {
			return false, err
		}
	} else {
		g.logger.Debug("Client denied from revoking a refresh token belonging to Client", slog.String("clientId", validationResult.Client.ClientId), slog.String("tokenClientId", token.ClientId))
	}

	return true, nil
}
