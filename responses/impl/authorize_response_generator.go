// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/gonewx/wicket"
	config_options "github.com/gonewx/wicket/config/options"
	resp_models "github.com/gonewx/wicket/responses/models"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// AuthorizeResponseGenerator The authorize response generator
type AuthorizeResponseGenerator struct {
	logger                 *slog.Logger
	clock                  services.SystemClock
	options                *config_options.WicketOptions
	TokenService           services.TokenService
	KeyMaterialService     services.KeyMaterialService
	AuthorizationCodeStore storage.AuthorizationCodeStore
}

func NewAuthorizeResponseGenerator(
	options *config_options.WicketOptions,
	clock services.SystemClock,
	tokenService services.TokenService,
	keyMaterialService services.KeyMaterialService,
	authorizationCodeStore storage.AuthorizationCodeStore,
	logger *slog.Logger,
) *AuthorizeResponseGenerator {
	return &AuthorizeResponseGenerator{
		options:                options,
		clock:                  clock,
		TokenService:           tokenService,
		KeyMaterialService:     keyMaterialService,
		AuthorizationCodeStore: authorizationCodeStore,
		logger:                 logger,
	}
}

func (g *AuthorizeResponseGenerator) Create(req *validators_models.ValidatedAuthorizeRequest) (*resp_models.AuthorizeResponse, error) {
	switch req.GrantType {
	case gois.GrantTypeAuthorizationCode:
		return g.createCodeFlow(req)
	case gois.GrantTypeImplicit:
		return g.createImplicitFlow(req, "")
	case gois.GrantTypeHybrid:
		return g.createHybridFlow(req)
	default:
		g.logger.Error("Unsupported grant type", slog.String("GrantType", req.GrantType))
	}
	return nil, fmt.Errorf("invalid grant type: %v", req.GrantType)
}

// createHybridFlow Creates the response for a hybrid flow request
func (g *AuthorizeResponseGenerator) createHybridFlow(req *validators_models.ValidatedAuthorizeRequest) (*resp_models.AuthorizeResponse, error) {
	g.logger.Debug("Creating Hybrid flow response")

	code, err := g.createCode(req)
	if err != nil {
		return nil, err
	}

	id, err := g.AuthorizationCodeStore.StoreAuthorizationCode(code)
	if err != nil {
		return nil, err
	}

	resposne, err := g.createImplicitFlow(req, id)
	if err != nil {
		return nil, err
	}

	resposne.Code = id

	return resposne, nil
}

// createCodeFlow Creates the response for a code flow request
func (g *AuthorizeResponseGenerator) createCodeFlow(req *validators_models.ValidatedAuthorizeRequest) (*resp_models.AuthorizeResponse, error) {
	g.logger.Debug("Creating authorization code flow response")

	code, err := g.createCode(req)
	if err != nil {
		return nil, err
	}

	id, err := g.AuthorizationCodeStore.StoreAuthorizationCode(code)
	if err != nil {
		return nil, err
	}

	response := resp_models.NewAuthorizeResponse()
	response.Request = req
	response.Code = id
	if req != nil {
		response.Issuer = req.IssuerName
		response.SessionState = req.GenerateSessionStateValue()
	}

	return response, nil
}

// createImplicitFlow Creates the response for a implicit flow request
func (g *AuthorizeResponseGenerator) createImplicitFlow(req *validators_models.ValidatedAuthorizeRequest, authorizationCode string) (*resp_models.AuthorizeResponse, error) {
	g.logger.Debug("Creating Implicit flow response")

	accessTokenValue := ""
	accessTokenLifetime := 0

	responseTypes := strings.Split(req.ResponseType, " ")

	if utils.Contains(responseTypes, gois.ResponseTypesToken) {
		tokenRequest := &responses_models.TokenCreationRequest{
			Subject: req.Subject,
			// implicit responses do not allow resource gap, so no resource gap filtering needed here
			ValidatedResources: req.ValidatedResources,
			ValidatedRequest:   req.ValidatedRequest,
		}
		accessToken, err := g.TokenService.CreateAccessToken(tokenRequest)
		if err != nil {
			return nil, err
		}
		accessTokenLifetime = accessToken.Lifetime
		accessTokenValue, err = g.TokenService.CreateSecurityToken(accessToken)
		if err != nil {
			return nil, err
		}
	}

	jwt := ""
	if utils.Contains(responseTypes, gois.ResponseTypesIdToken) {
		var err error
		stateHash := ""
		if g.options.EmitStateHash && strings.TrimSpace(req.State) != "" {
			credential, err := g.KeyMaterialService.GetSigningCredentials(req.Client.AllowedIdentityTokenSigningAlgorithms)
			if err != nil || credential == nil {
				return nil, fmt.Errorf(" %w : No signing credential is configured.", err)
			}
			algorithm := credential.Algorithm
			stateHash, err = utils.CreateHashClaimValue(req.State, algorithm)
			if err != nil {
				return nil, err
			}
		}
		tokenRequest := &responses_models.TokenCreationRequest{
			ValidatedRequest:         req.ValidatedRequest,
			Subject:                  req.Subject,
			ValidatedResources:       req.ValidatedResources,
			Nonce:                    req.Raw.Get(gois.AuthorizeRequestNonce),
			IncludeAllIdentityClaims: !req.AccessTokenRequested(),
			AccessTokenToHash:        accessTokenValue,
			AuthorizationCodeToHash:  authorizationCode,
			StateHash:                stateHash,
		}
		idToken, err := g.TokenService.CreateIdentityToken(tokenRequest)
		if err != nil {
			return nil, err
		}
		jwt, err = g.TokenService.CreateSecurityToken(idToken)
		if err != nil {
			return nil, err
		}
	}
	response := resp_models.NewAuthorizeResponse()
	response.Request = req
	response.AccessToken = accessTokenValue
	response.AccessTokenLifetime = accessTokenLifetime
	response.IdentityToken = jwt
	response.SessionState = req.GenerateSessionStateValue()
	return response, nil
}

// createCode Creates an authorization code
func (g *AuthorizeResponseGenerator) createCode(req *validators_models.ValidatedAuthorizeRequest) (*storage_models.AuthorizationCode, error) {
	g.logger.Debug("Creating authorization code")

	stateHash := ""
	if req.State != "" && g.options.EmitStateHash {
		credential, err := g.KeyMaterialService.GetSigningCredentials(req.Client.AllowedIdentityTokenSigningAlgorithms)
		if err != nil {
			return nil, err
		}
		if credential == nil {
			return nil, errors.New("No signing credential is configured.")
		}

		algorithm := credential.Algorithm
		stateHash, err = utils.CreateHashClaimValue(req.State, algorithm)
		if err != nil {
			return nil, err
		}
	}

	code := storage_models.NewAuthorizationCode()
	code.CreationTime = g.clock.Now()
	code.ClientId = req.Client.ClientId
	code.Lifetime = req.Client.AuthorizationCodeLifetime
	code.Subject = req.Subject
	code.SessionId = req.SessionId
	code.Description = req.Description
	code.CodeChallenge = utils.Sha256(req.CodeChallenge)
	code.CodeChallengeMethod = req.CodeChallengeMethod
	code.IsOpenId = req.IsOpenIdRequest
	code.RequestedScopes = req.ValidatedResources.RawScopeValues()
	code.RequestedResourceGaps = req.RequestedResourceIndiators
	code.RedirectUri = req.RedirectUri
	code.Nonce = req.Nonce
	code.StateHash = stateHash
	code.WasConsentShown = req.WasConsentShown

	return code, nil
}
