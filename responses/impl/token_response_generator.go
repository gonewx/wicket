// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/extensions"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// TokenResponseGenerator The default token response generator
type TokenResponseGenerator struct {
	logger              *slog.Logger
	tokenService        services.TokenService
	refreshTokenService services.RefreshTokenService
	scopeParser         validators.ScopeParser
	resources           storage.ResourceStore
	clients             storage.ClientStore
	backchannelRequests storage.BackchannelAuthenticationRequestStore
	clock               services.SystemClock
}

func NewTokenResponseGenerator(
	clock services.SystemClock,
	tokenService services.TokenService,
	refreshTokenService services.RefreshTokenService,
	scopeParser validators.ScopeParser,
	resources storage.ResourceStore,
	clients storage.ClientStore,
	logger *slog.Logger,
) *TokenResponseGenerator {
	return &TokenResponseGenerator{
		logger:              logger,
		tokenService:        tokenService,
		refreshTokenService: refreshTokenService,
		scopeParser:         scopeParser,
		resources:           resources,
		clients:             clients,
		clock:               clock,
	}
}

func NewTokenResponseGeneratorWithBackchannelRequests(
	clock services.SystemClock,
	tokenService services.TokenService,
	refreshTokenService services.RefreshTokenService,
	scopeParser validators.ScopeParser,
	resources storage.ResourceStore,
	clients storage.ClientStore,
	backchannelRequests storage.BackchannelAuthenticationRequestStore,
	logger *slog.Logger,
) *TokenResponseGenerator {
	g := NewTokenResponseGenerator(clock, tokenService, refreshTokenService, scopeParser, resources, clients, logger)
	g.backchannelRequests = backchannelRequests
	return g
}

// Processes the response.
func (g *TokenResponseGenerator) Handle(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	switch request.ValidatedRequest.GrantType {
	case gois.GrantTypeClientCredentials:
		return g.handleClientCredentialsRequest(ctx, request)
	case gois.GrantTypePassword:
		return g.handlePasswordRequest(ctx, request)
	case gois.GrantTypeAuthorizationCode:
		return g.handleAuthorizationCodeRequest(ctx, request)
	case gois.GrantTypeRefreshToken:
		return g.handleRefreshTokenRequest(ctx, request)
	case gois.GrantTypeDeviceCode:
		return g.handleDeviceCodeRequest(ctx, request)
	case gois.GrantTypeBackchannelAuthentication:
		return g.handleBackchannelAuthenticationRequest(ctx, request)
	default:
		return g.handleExtensionGrant(ctx, request)
	}
}

// Creates the response for an client credentials request.
func (g *TokenResponseGenerator) handleClientCredentialsRequest(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	g.logger.Debug("Creating response for client credentials request")

	return g.handleTokenRequest(ctx, request)
}

// Creates the response for an authorization code request.
func (g *TokenResponseGenerator) handlePasswordRequest(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	g.logger.Debug("Creating response for password request")

	return g.handleTokenRequest(ctx, request)
}

// Creates the response for a refresh token request.
func (g *TokenResponseGenerator) handleAuthorizationCodeRequest(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	g.logger.Debug("Creating response for authorization code request")

	// access token
	accessToken, refreshToken, err := g.createAccessToken(ctx, request.ValidatedRequest)
	if err != nil {
		return nil, err
	}

	response := &responses_models.TokenResponse{
		AccessToken:         accessToken,
		AccessTokenLifetime: request.ValidatedRequest.AccessTokenLifetime,
		Custom:              request.CustomResponse,
		Scope:               strings.Join(request.ValidatedRequest.ValidatedResources.RawScopeValues(), " "),
	}

	// refresh token
	if refreshToken != "" {
		response.RefreshToken = refreshToken
	}

	// id token
	if request.ValidatedRequest.AuthorizationCode.IsOpenId {
		// load the client that belongs to the authorization code
		var client *storage_models.Client
		if request.ValidatedRequest.AuthorizationCode.ClientId != "" {
			// todo: do we need this check?
			client, err = extensions.FindEnabledClientById(ctx, g.clients, request.ValidatedRequest.ClientId)
		}
		if err != nil || client == nil {
			return nil, errors.New("Client does not exist anymore.")
		}

		tokenRequest := &responses_models.TokenCreationRequest{
			Subject:            request.ValidatedRequest.AuthorizationCode.Subject,
			ValidatedResources: request.ValidatedRequest.ValidatedResources,
			Nonce:              request.ValidatedRequest.AuthorizationCode.Nonce,
			AccessTokenToHash:  response.AccessToken,
			StateHash:          request.ValidatedRequest.AuthorizationCode.StateHash,
			ValidatedRequest:   request.ValidatedRequest.ValidatedRequest,
		}

		idToken, err := g.tokenService.CreateIdentityToken(ctx, tokenRequest)
		if err != nil {
			return nil, err
		}

		jwt, err := g.tokenService.CreateSecurityToken(ctx, idToken)
		if err != nil {
			return nil, err
		}

		response.IdentityToken = jwt
	}

	return response, nil
}

// Creates the response for a refresh token request.
func (g *TokenResponseGenerator) handleRefreshTokenRequest(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	g.logger.Debug("Creating response for refresh code request")

	accessToken := request.ValidatedRequest.RefreshToken.GetAccessToken(request.ValidatedRequest.RequestedResourceGap)

	mustUpdate := accessToken == nil || request.ValidatedRequest.Client.UpdateAccessTokenClaimsOnRefresh

	var err error
	if mustUpdate {
		creationRequest := &responses_models.TokenCreationRequest{
			Subject:            request.ValidatedRequest.RefreshToken.Subject,
			Description:        request.ValidatedRequest.RefreshToken.Description,
			ValidatedRequest:   request.ValidatedRequest.ValidatedRequest,
			ValidatedResources: request.ValidatedRequest.ValidatedResources,
		}

		accessToken, err = g.tokenService.CreateAccessToken(ctx, creationRequest)
		if err != nil {
			return nil, err
		}
	} else {
		// todo: do we want a new JTI?
		accessToken.CreationTime = g.clock.Now()
		accessToken.Lifetime = request.ValidatedRequest.AccessTokenLifetime
	}

	accessTokenString, err := g.tokenService.CreateSecurityToken(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	request.ValidatedRequest.RefreshToken.SetAccessToken(accessToken, request.ValidatedRequest.RequestedResourceGap)

	handle, err := g.refreshTokenService.UpdateRefreshToken(
		ctx,
		&responses_models.RefreshTokenUpdateRequest{
			Handle:               request.ValidatedRequest.RefreshTokenHandle,
			RefreshToken:         request.ValidatedRequest.RefreshToken,
			Client:               request.ValidatedRequest.Client,
			AccessToken:          accessToken,
			RequestedResourceGap: request.ValidatedRequest.RequestedResourceGap,
			MustUpdate:           mustUpdate,
		},
	)
	if err != nil {
		if errors.Is(err, storage.ErrVersionConflict) {
			return nil, fmt.Errorf("%w: %w", gois.TokenErrorsInvalidGrant, err)
		}
		return nil, err
	}

	idToken, err := g.CreateIdTokenFromRefreshTokenRequest(ctx, request.ValidatedRequest, accessTokenString)
	if err != nil {
		return nil, err
	}

	return &responses_models.TokenResponse{
		IdentityToken:       idToken,
		AccessToken:         accessTokenString,
		AccessTokenLifetime: request.ValidatedRequest.AccessTokenLifetime,
		RefreshToken:        handle,
		Custom:              request.CustomResponse,
		Scope:               strings.Join(request.ValidatedRequest.ValidatedResources.RawScopeValues(), " "),
	}, nil
}

// Processes the response for device code grant request.
func (g *TokenResponseGenerator) handleDeviceCodeRequest(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	g.logger.Debug("Creating response for device code request")

	// access token
	accessToken, refreshToken, err := g.createAccessToken(ctx, request.ValidatedRequest)
	if err != nil {
		return nil, err
	}

	response := &responses_models.TokenResponse{
		AccessToken:         accessToken,
		AccessTokenLifetime: request.ValidatedRequest.AccessTokenLifetime,
		Custom:              request.CustomResponse,
		Scope:               strings.Join(request.ValidatedRequest.ValidatedResources.RawScopeValues(), " "),
	}

	// refresh token
	if refreshToken != "" {
		response.RefreshToken = refreshToken
	}

	// id token
	if request.ValidatedRequest.DeviceCode.IsOpenId {
		// load the client that belongs to the authorization code
		var client *storage_models.Client
		if request.ValidatedRequest.DeviceCode.ClientId != "" {
			// todo: do we need this check?
			client, err = extensions.FindEnabledClientById(ctx, g.clients, request.ValidatedRequest.ClientId)
		}
		if err != nil || client == nil {
			return nil, errors.New("Client does not exist anymore.")
		}

		tokenRequest := &responses_models.TokenCreationRequest{
			Subject:            request.ValidatedRequest.DeviceCode.Subject,
			ValidatedResources: request.ValidatedRequest.ValidatedResources,
			AccessTokenToHash:  response.AccessToken,
			ValidatedRequest:   request.ValidatedRequest.ValidatedRequest,
		}

		idToken, err := g.tokenService.CreateIdentityToken(ctx, tokenRequest)
		if err != nil {
			return nil, err
		}

		jwt, err := g.tokenService.CreateSecurityToken(ctx, idToken)
		if err != nil {
			return nil, err
		}

		response.IdentityToken = jwt
	}

	return response, nil
}

func (g *TokenResponseGenerator) handleBackchannelAuthenticationRequest(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	response, err := g.handleTokenRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	state := request.ValidatedRequest.BackchannelAuthenticationRequest
	if state != nil && g.backchannelRequests != nil {
		state.Status = storage_models.BackchannelAuthenticationRequestStatusConsumed
		if err := g.backchannelRequests.UpdateBackchannelAuthenticationRequest(ctx, state.RequestId, state); err != nil {
			return nil, err
		}
	}
	return response, nil
}

// Creates the response for an extension grant request.
func (g *TokenResponseGenerator) handleExtensionGrant(ctx context.Context, request *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	g.logger.Debug("Creating response for extension grant request")

	return g.handleTokenRequest(ctx, request)
}

func (g *TokenResponseGenerator) handleTokenRequest(ctx context.Context, validationResult *validators_models.TokenRequestValidationResult) (*responses_models.TokenResponse, error) {
	accessToken, refreshToken, err := g.createAccessToken(ctx, validationResult.ValidatedRequest)
	if err != nil {
		return nil, err
	}
	response := &responses_models.TokenResponse{
		AccessToken:         accessToken,
		AccessTokenLifetime: validationResult.ValidatedRequest.AccessTokenLifetime,
		Custom:              validationResult.CustomResponse,
		Scope:               strings.Join(validationResult.ValidatedRequest.ValidatedResources.RawScopeValues(), " "),
	}

	if refreshToken != "" {
		response.RefreshToken = refreshToken
	}

	return response, nil
}

func (g *TokenResponseGenerator) createAccessToken(ctx context.Context, request *validators_models.ValidatedTokenRequest) (string, string, error) {
	tokenRequest := &responses_models.TokenCreationRequest{
		Subject:            request.Subject,
		ValidatedResources: request.ValidatedResources,
		ValidatedRequest:   request.ValidatedRequest,
	}

	createRefreshToken := request.ValidatedResources.Resources.OfflineAccess
	var authorizedScopes []string
	var authorizedResourceGaps []string

	if request.AuthorizationCode != nil {
		// load the client that belongs to the authorization code
		var client *storage_models.Client
		var err error
		if request.AuthorizationCode.ClientId != "" {
			// todo: do we need this check?
			client, err = extensions.FindEnabledClientById(ctx, g.clients, request.AuthorizationCode.ClientId)
		}
		if err != nil || client == nil {
			return "", "", errors.New("Client does not exist anymore.")
		}

		tokenRequest.Subject = request.AuthorizationCode.Subject
		tokenRequest.Description = request.AuthorizationCode.Description

		authorizedScopes = request.AuthorizationCode.RequestedScopes
		authorizedResourceGaps = cloneResourceGaps(request.AuthorizationCode.RequestedResourceGaps)
	} else {
		if request.BackchannelAuthenticationRequest != nil {
			var client *storage_models.Client
			var err error
			if request.BackchannelAuthenticationRequest.ClientId != "" {
				client, err = extensions.FindEnabledClientById(ctx, g.clients, request.BackchannelAuthenticationRequest.ClientId)
			}
			if err != nil || client == nil {
				return "", "", errors.New("Client does not exist anymore.")
			}
			tokenRequest.Subject = request.BackchannelAuthenticationRequest.Subject
			authorizedScopes = request.BackchannelAuthenticationRequest.RequestedScopes
			authorizedResourceGaps = cloneResourceGaps(request.BackchannelAuthenticationRequest.RequestedResourceGaps)
		} else {
			if request.DeviceCode != nil {
				var client *storage_models.Client
				var err error
				if request.DeviceCode.ClientId != "" {
					// todo: do we need this check?
					client, err = extensions.FindEnabledClientById(ctx, g.clients, request.DeviceCode.ClientId)
				}

				if err != nil || client == nil {
					return "", "", errors.New("Client does not exist anymore.")
				}

				tokenRequest.Subject = request.DeviceCode.Subject
				tokenRequest.Description = request.DeviceCode.Description

				authorizedScopes = request.DeviceCode.RequestedScopes
				authorizedResourceGaps = []string{}
			} else {
				authorizedScopes = request.ValidatedResources.RawScopeValues()
				authorizedResourceGaps = selectedResourceGaps(request.RequestedResourceGap)
			}
		}
	}

	at, err := g.tokenService.CreateAccessToken(ctx, tokenRequest)
	if err != nil {
		return "", "", err
	}
	accessToken, err := g.tokenService.CreateSecurityToken(ctx, at)
	if err != nil {
		return "", "", err
	}

	if createRefreshToken {
		rtRequest := &responses_models.RefreshTokenCreationRequest{
			Client:                 request.Client,
			Subject:                tokenRequest.Subject,
			Description:            tokenRequest.Description,
			AuthorizedScopes:       authorizedScopes,
			AuthorizedResourceGaps: authorizedResourceGaps,
			AccessToken:            at,
			RequestedResourceGap:   request.RequestedResourceGap,
		}

		refreshToken, err := g.refreshTokenService.CreateRefreshToken(ctx, rtRequest)
		if err != nil {
			return "", "", err
		}

		return accessToken, refreshToken, nil
	}

	return accessToken, "", nil
}

func cloneResourceGaps(values []string) []string {
	if values == nil {
		return []string{}
	}
	return append([]string(nil), values...)
}

func selectedResourceGaps(value string) []string {
	if value == "" {
		return []string{}
	}
	return []string{value}
}

func (g *TokenResponseGenerator) CreateIdTokenFromRefreshTokenRequest(ctx context.Context, request *validators_models.ValidatedTokenRequest, newAccessToken string) (string, error) {
	if utils.Contains(request.RefreshToken.AuthorizedScopes, gois.StandardScopesOpenId) {
		tokenRequest := &responses_models.TokenCreationRequest{
			Subject:            request.RefreshToken.Subject,
			ValidatedResources: request.ValidatedResources,
			ValidatedRequest:   request.ValidatedRequest,
			AccessTokenToHash:  newAccessToken,
		}

		idToken, err := g.tokenService.CreateIdentityToken(ctx, tokenRequest)
		if err != nil {
			return "", err
		}

		return g.tokenService.CreateSecurityToken(ctx, idToken)
	}

	return "", nil
}
