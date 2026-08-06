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
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/extensions"
	"github.com/gonewx/wicket/models"
	"github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/services"
	storage "github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// TokenValidator  for the token validator
type TokenValidator struct {
	logger                     *slog.Logger
	options                    *config_options.WicketOptions
	issuerNameService          services.IssuerNameService
	referenceTokenStore        storage.ReferenceTokenStore
	customValidator            validators.CustomTokenValidator
	clients                    storage.ClientStore
	profile                    services.ProfileService
	keys                       services.KeyMaterialService
	sessionCoordinationService services.SessionCoordinationService
	clock                      services.SystemClock
}

func NewTokenValidator(
	logger *slog.Logger,
	options *config_options.WicketOptions,
	issuerNameService services.IssuerNameService,
	referenceTokenStore storage.ReferenceTokenStore,
	customValidator validators.CustomTokenValidator,
	clients storage.ClientStore,
	profile services.ProfileService,
	keys services.KeyMaterialService,
	sessionCoordinationService services.SessionCoordinationService,
	clock services.SystemClock,
) *TokenValidator {
	return &TokenValidator{
		logger:                     logger,
		options:                    options,
		issuerNameService:          issuerNameService,
		referenceTokenStore:        referenceTokenStore,
		customValidator:            customValidator,
		clients:                    clients,
		profile:                    profile,
		keys:                       keys,
		sessionCoordinationService: sessionCoordinationService,
		clock:                      clock,
	}
}

// ValidateAccessToken Validates an access token. A non-nil error reports an
// infrastructure failure so the caller can distinguish it from an invalid-token
// result.
func (v *TokenValidator) ValidateAccessToken(ctx context.Context, token string, expectedScope string) (*validators_models.TokenValidationResult, error) {
	v.logger.Debug("Start access token validation")

	result := validators_models.NewTokenValidationResult()

	if strings.Contains(token, ".") {
		if len(token) > v.options.InputLengthRestrictions.Jwt {
			result.Error = gois.ProtectedResourceErrorsInvalidToken
			result.Description = "Token too long"
			return result, nil
		}

		keys, err := v.keys.GetValidationKeys(ctx)
		if err != nil {
			v.logger.Error("Error getting validation keys", slog.String("error", err.Error()))
			return nil, err
		}

		result = v.validateJwt(ctx, token, keys, true, "")
	} else {
		if len(token) > v.options.InputLengthRestrictions.TokenHandle {
			v.logger.Error("token handle too long")

			result.Error = gois.ProtectedResourceErrorsInvalidToken
			result.Description = "Token handle too long"
			return result, nil
		}

		result = v.validateReferenceAccessToken(ctx, token)
	}

	if result.Error != nil {
		return result, nil
	}

	// make sure client is still active (if client_id claim is present)
	clientClaim := utils.FirstOrDefaultPred(result.Claims, func(c *claimspkg.Claim) bool {
		return c.Type == gois.JwtClaimTypesClientId
	})

	if clientClaim != nil {
		client, err := extensions.FindEnabledClientById(ctx, v.clients, clientClaim.Value.(string))
		if err != nil || client == nil {
			v.logger.Error("Client deleted or disabled", slog.String("clientId", clientClaim.Value.(string)))
			return v.invalid(gois.ProtectedResourceErrorsInvalidToken), nil
		}

	}

	// make sure user is still active (if sub claim is present)
	subClaim := utils.FirstOrDefaultPred(result.Claims, func(c *claimspkg.Claim) bool {
		return c.Type == gois.JwtClaimTypesSubject
	})

	if subClaim != nil {
		principal := claims.NewClaimsPrincipal(
			claims.WithClaimsPrincipalIdentity(
				claims.NewClaimsIdentity(
					claims.WithAuthenticationType("tokenvalidator"),
					claims.WithClaims(result.Claims),
				),
			),
		)

		if result.ReferenceTokenId != "" && len(principal.Identities) > 0 {
			principal.Identities[0].AddClaim(
				claims.NewClaim(
					claims.WithClaimType(gois.JwtClaimTypesReferenceTokenId),
					claims.WithClaimValue(result.ReferenceTokenId),
				),
			)
		}

		isActiveCtx := contexts.NewIsActiveContext(principal, result.Client, gois.ProfileIsActiveCallersAccessTokenValidation)
		v.profile.IsActive(isActiveCtx)

		if !isActiveCtx.IsActive {
			v.logger.Error("User marked as not active", slog.String("subjectId", subClaim.Value.(string)))
			return v.invalid(gois.ProtectedResourceErrorsInvalidToken), nil
		}

		sub := subClaim.Value.(string)
		sid := principal.FindFirst(gois.JwtClaimTypesSessionId)
		if sid != nil {
			subjectId, ok := sid.Value.(string)
			if !ok {
				subjectId = ""
			}
			sessionResult, err := v.sessionCoordinationService.ValidateSession(ctx,
				&services.SessionValidationRequest{
					SubjectId: sub,
					SessionId: subjectId,
					Client:    result.Client,
					Type:      services.SessionValidationTypeAccessToken,
				},
			)

			if err != nil {
				return nil, err
			}
			if !sessionResult {
				v.logger.Error("Server-side session invalid for subject Id and session Id.", slog.String("subjectId", sub), slog.String("sessionId", subjectId))
				return v.invalid(gois.ProtectedResourceErrorsInvalidToken), nil
			}
		}
	}

	// check expected scope(s)
	if expectedScope != "" {
		scope := utils.FirstOrDefaultPred(result.Claims, func(c *claimspkg.Claim) bool {
			return c.Type == gois.JwtClaimTypesScope && c.Value == expectedScope
		})
		if scope == nil {
			v.logger.Error("Checking for expected scopefailed", slog.String("expectedScope", expectedScope))
			return v.invalid(gois.ProtectedResourceErrorsInsufficientScope), nil
		}
	}

	v.logger.Debug("Calling into custom token validator", slog.String("type", fmt.Sprintf("%T", v.customValidator)))

	customResult := v.customValidator.ValidateAccessToken(result)
	if customResult.Error != nil {
		v.logger.Error("Custom validator failed", slog.String("type", customResult.Error.Error()))
		return customResult, nil
	}

	return customResult, nil
}

// ValidateIdentityToken Validates an identity token. A non-nil error reports an
// infrastructure failure so the caller can distinguish it from an invalid-token
// result.
func (v *TokenValidator) ValidateIdentityToken(ctx context.Context, token string, clientId string, validateLifetime bool) (*validators_models.TokenValidationResult, error) {
	v.logger.Debug("Start identity token validation")

	if len(token) > v.options.InputLengthRestrictions.Jwt {
		v.logger.Error("JWT too long")
		return v.invalid(gois.ProtectedResourceErrorsInvalidToken), nil
	}

	if clientId == "" {
		var err error
		clientId, err = v.getClientIdFromJwt(token)
		if err != nil || clientId == "" {
			v.logger.Error("No clientId supplied, can't find id in identity token.")
			return v.invalid(gois.ProtectedResourceErrorsInvalidToken), nil
		}
	}

	client, err := extensions.FindEnabledClientById(ctx, v.clients, clientId)
	if err != nil || client == nil {
		v.logger.Error("Unknown or disabled client", slog.String("clientId", clientId))
		return v.invalid(gois.ProtectedResourceErrorsInvalidToken), nil
	}

	v.logger.Debug("Client found", slog.String("clientId", clientId), slog.String("clientName", client.ClientName))

	keys, err := v.keys.GetValidationKeys(ctx)
	if err != nil {
		v.logger.Error("No validate keys")
		return nil, err
	}

	result := v.validateJwt(ctx, token, keys, validateLifetime, clientId)

	result.Client = client

	if result.Error != nil {
		return result, nil
	}

	v.logger.Debug("Calling into custom token validator", slog.String("type", fmt.Sprintf("%T", v.customValidator)))

	customResult := v.customValidator.ValidateIdentityToken(result)

	if customResult.Error != nil {
		v.logger.Debug("Custom validator failed:", slog.String("error", customResult.Error.Error()))
		return customResult, nil
	}

	return customResult, nil
}

func (v *TokenValidator) parseJwt(jwtString string, validationKeys []*models.SecurityKeyInfo, validateLifetime bool, audience string) (jwt.Token, error) {
	opts := make([]jwt.ParseOption, 0)
	opts = append(opts, jwt.WithValidate(true))
	opts = append(opts, jwt.WithVerify(true))
	opts = append(opts, jwt.WithIssuer(v.issuerNameService.GetCurrent()))

	set := jwk.NewSet()
	for _, key := range validationKeys {
		k, err := jwk.Import(key.Key)
		if err != nil {
			return nil, err
		}
		err = jwk.AssignKeyID(k)
		if err != nil {
			return nil, err
		}

		_ = k.Set(jwk.AlgorithmKey, key.SigningAlgorithm)
		if err := set.AddKey(k); err != nil {
			v.logger.Error("Key add key error", slog.String("error", err.Error()))
			return nil, err
		}
	}

	pubSet, err := jwk.PublicSetOf(set)
	if err != nil {
		v.logger.Error("Key set public key error", slog.String("error", err.Error()))
		return nil, err
	}

	opts = append(opts, jwt.WithKeySet(pubSet))

	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	} else {
		// if no audience is specified, we make at least sure that it is an access token
		if v.options.AccessTokenJwtType != "" {
			jwsMsg, err := jws.Parse([]byte(jwtString))
			if err != nil {
				return nil, err
			}
			typ, ok := jwsMsg.Signatures()[0].ProtectedHeaders().Type()
			if !ok {
				return nil, errors.New("typ not found")
			}
			if typ != v.options.AccessTokenJwtType {
				return nil, errors.New("typ not match")
			}
		}
	}
	return jwt.Parse([]byte(jwtString), opts...)
}

func (v *TokenValidator) validateJwt(ctx context.Context, jwtString string, validationKeys []*models.SecurityKeyInfo, validateLifetime bool, audience string) *validators_models.TokenValidationResult {
	token, err := v.parseJwt(jwtString, validationKeys, validateLifetime, audience)
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			v.logger.Error("JWT token validation expired error", slog.String("error", err.Error()))
			return v.invalid(gois.ProtectedResourceErrorsExpiredToken)
		} else {
			v.logger.Error("JWT token validation error", slog.String("error", err.Error()))
			return v.invalid(gois.ProtectedResourceErrorsInvalidToken)
		}
	}

	// 以下逻辑有较多改动

	// if access token contains an ID, log it
	// jwtId := token.JwtID()

	// load the client that belongs to the client_id claim
	var client *storage_models.Client
	var clientId any
	if err := token.Get(gois.JwtClaimTypesClientId, &clientId); err == nil {
		cid, ok := clientId.(string)
		if !ok || cid == "" {
			v.logger.Error("No client id in token")
			return v.invalid(gois.ProtectedResourceErrorsInvalidToken)
		}

		client, err = extensions.FindEnabledClientById(ctx, v.clients, cid)
		if err != nil || client == nil {
			v.logger.Error("Client deleted or disabled", slog.String("clientId", cid))
			return v.invalid(gois.ProtectedResourceErrorsInvalidToken)
		}
	}

	issuer, _ := token.Issuer()
	if issuer == "" {
		issuer = claimspkg.DefaultIssuer
	}

	resultClaims := make([]*claimspkg.Claim, 0)
	for _, k := range token.Keys() {
		var value any
		if err := token.Get(k, &value); err != nil {
			continue
		}
		if k == gois.JwtClaimTypesScope {
			// check the scope format (array vs space delimited string)
			scopes, err := parseScopes(value)
			if err != nil {
				return v.invalid(err)
			}

			for _, scope := range scopes {
				resultClaims = append(resultClaims, &claimspkg.Claim{
					Type:           k,
					Value:          scope,
					Issuer:         issuer,
					OriginalIssuer: issuer,
				})
			}
		} else {
			// jwx surfaces registered temporal claims as time.Time; the claim
			// value must stay the numeric-date form the token carried
			// (RFC 7519 §2), so downstream responses serialize numbers.
			if instant, ok := value.(time.Time); ok {
				value = instant.Unix()
			}
			resultClaims = append(resultClaims, &claimspkg.Claim{
				Type:           k,
				Value:          value,
				Issuer:         issuer,
				OriginalIssuer: issuer,
			})
		}

	}

	result := validators_models.NewTokenValidationResult()
	result.Claims = resultClaims
	result.Client = client
	result.Jwt = jwtString

	return result
}

func parseScope(s string) []string {
	if strings.Contains(s, " ") {
		return strings.Split(s, " ")
	}

	return []string{s}
}

func parseScopes(value any) ([]string, error) {
	results := make([]string, 0)
	switch value := value.(type) {
	case []any:
		scopes := value
		for _, scope := range scopes {
			scope, ok := scope.(string)
			if !ok {
				return nil, fmt.Errorf("invalid scope")
			}
			results = append(results, parseScope(scope)...)
		}
	case string:
		results = append(results, parseScope(value)...)
	default:
		return nil, fmt.Errorf("invalid scope")
	}

	return results, nil
}

func (v *TokenValidator) getClientIdFromJwt(token string) (string, error) {

	tk, err := jwt.Parse([]byte(token), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		v.logger.Error("Malformed JWT token", slog.String("error", err.Error()))
		return "", err

	}

	aud, _ := tk.Audience()
	clientId := utils.FirstOrDefault(aud)

	if err != nil {
		v.logger.Error("Malformed JWT token", slog.String("error", err.Error()))
		return "", err

	}

	return clientId, nil
}

func (v *TokenValidator) validateReferenceAccessToken(ctx context.Context, tokenHandle string) *validators_models.TokenValidationResult {
	token, err := v.referenceTokenStore.GetReferenceToken(ctx, tokenHandle)
	if err != nil || token == nil {
		v.logger.Error("Invalid reference token")
		return v.invalid(gois.ProtectedResourceErrorsInvalidToken)
	}

	if v.clock.Now().After(token.CreationTime.Add(time.Duration(token.Lifetime) * time.Second)) {
		v.logger.Error("Reference token expired")
		return v.invalid(gois.ProtectedResourceErrorsExpiredToken)
	}

	// load the client that is defined in the token
	var client *storage_models.Client
	if token.ClientId != "" {
		client, err = extensions.FindEnabledClientById(ctx, v.clients, token.ClientId)
	}

	if err != nil || client == nil {
		v.logger.Error("lient deleted or disabled", slog.String("clientId", token.ClientId))
		return v.invalid(gois.ProtectedResourceErrorsInvalidToken)
	}

	result := validators_models.NewTokenValidationResult()
	result.Client = client
	result.Claims = v.referenceTokenToClaims(token)

	return result
}

func (v *TokenValidator) referenceTokenToClaims(token *storage_models.Token) []*claimspkg.Claim {
	claims := make([]*claimspkg.Claim, 0)
	claims = append(claims, &claimspkg.Claim{
		Type:  gois.JwtClaimTypesIssuer,
		Value: token.Issuer,
	})

	claims = append(claims, &claimspkg.Claim{
		Type:  gois.JwtClaimTypesNotBefore,
		Value: token.CreationTime.Unix(),
	})

	claims = append(claims, &claimspkg.Claim{
		Type:  gois.JwtClaimTypesIssuedAt,
		Value: token.CreationTime.Unix(),
	})

	claims = append(claims, &claimspkg.Claim{
		Type:  gois.JwtClaimTypesExpiration,
		Value: token.CreationTime.Add(time.Duration(token.Lifetime) * time.Second).Unix(),
	})

	for _, aud := range token.Audiences {
		claims = append(claims, &claimspkg.Claim{
			Type:  gois.JwtClaimTypesAudience,
			Value: aud,
		})
	}
	claims = append(claims, token.Claims...)

	return claims
}

func (v *TokenValidator) invalid(err error) *validators_models.TokenValidationResult {
	result := validators_models.NewTokenValidationResult()
	result.Error = err
	return result
}
