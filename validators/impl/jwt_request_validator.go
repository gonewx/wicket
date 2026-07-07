// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package impl

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	tokjwt "github.com/gonewx/wicket/tokens/jwt"
	"github.com/gonewx/wicket/utils"
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type JwtRequestValidator struct {
	options           *config_options.WicketOptions
	issuerNameService services.IssuerNameService
	logger            *slog.Logger
	audienceUri       string
}

func NewJwtRequestValidator(
	options *config_options.WicketOptions,
	issuerNameService services.IssuerNameService,
	logger *slog.Logger,
) *JwtRequestValidator {
	return &JwtRequestValidator{
		options:           options,
		issuerNameService: issuerNameService,
		logger:            logger,
	}
}

func (v *JwtRequestValidator) AudienceUri() string {
	if strings.TrimSpace(v.audienceUri) == "" {
		return v.issuerNameService.GetCurrent()
	}
	return v.audienceUri
}

func (v *JwtRequestValidator) SetAudienceUri(audienceUri string) {
	v.audienceUri = audienceUri
}

func (v *JwtRequestValidator) Validate(ctx *validators_contexts.JwtRequestValidationContext) (*validators_models.JwtRequestValidationResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}

	if ctx.Client == nil {
		return nil, fmt.Errorf("client is nil")
	}

	if strings.TrimSpace(ctx.JwtTokenString) == "" {
		return nil, fmt.Errorf("JwtTokenString is nil")
	}

	trustedKeys := ctx.Client.GetKeys()

	if trustedKeys.Len() == 0 {
		return nil, fmt.Errorf("client has no keys : ")

	}

	jwtSecurityToken, err := v.ValidateJwt(ctx, trustedKeys)
	if err != nil {
		return nil, err
	}

	_, tryGetRequest := jwtSecurityToken.Get(gois.AuthorizeRequestRequest)
	_, tryGetRequestUri := jwtSecurityToken.Get(gois.AuthorizeRequestRequestUri)
	if tryGetRequest || tryGetRequestUri {
		return nil, fmt.Errorf("JWT payload must not contain request or request_uri")
	}

	payload := v.ProcessPayload(ctx, jwtSecurityToken)

	result := validators_models.NewJwtRequestValidationResult()
	result.Payload = payload

	return result, nil
}

func (v *JwtRequestValidator) ValidateJwt(ctx *validators_contexts.JwtRequestValidationContext, keys jwk.Set) (jwt.Token, error) {
	pubSet, _ := jwk.PublicSetOf(keys)

	token, err := jwt.Parse([]byte(ctx.JwtTokenString), jwt.WithKeySet(pubSet))
	if err != nil {
		return nil, err
	}

	validateOpts := []jwt.ValidateOption{
		jwt.WithIssuer(ctx.Client.ClientId),
		jwt.WithAudience(v.AudienceUri()),
	}

	// TODO: strictJarValidation
	var strictJarValidation bool
	if ctx.StrictJarValidation != nil {
		strictJarValidation = *ctx.StrictJarValidation
	} else {
		strictJarValidation = v.options.StrictJarValidation
	}
	if strictJarValidation {
		validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
			jwsMsg, err := jws.Parse([]byte(ctx.JwtTokenString))
			if err != nil {
				return jwt.NewValidationError(err)
			}
			typ, ok := jwsMsg.Signatures()[0].ProtectedHeaders().Get("typ")
			if !ok {
				return jwt.NewValidationError(fmt.Errorf("cannot found type [%s]", typ))
			}

			if typ != string(gois.JwtTypesAuthorizationRequest) {
				return jwt.NewValidationError(fmt.Errorf("invalid type [%s]", typ))
			}
			return nil
		})
		validateOpts = append(validateOpts, jwt.WithValidator(validator))
	}

	// Note: jwx validates the expiration by default
	err = jwt.Validate(token, validateOpts...)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// Processes the JWT contents
func (v *JwtRequestValidator) ProcessPayload(validationCtx *validators_contexts.JwtRequestValidationContext, token jwt.Token) []*claimspkg.Claim {
	ctx := context.Background()

	// filter JWT validation values
	filter := gois.JwtRequestClaimTypesFilter
	if validationCtx.IncludeJti {
		// don't filter out the jti claim
		for i, v := range filter {
			if v == tokjwt.JwtRegisteredClaimNamesJti {
				filter = append(filter[:i], filter[i+1:]...)
				break
			}
		}
	}

	claims := make([]*claimspkg.Claim, 0)

	issuer, ok := token.Get(tokjwt.JwtRegisteredClaimNamesSub)
	if !ok {
		issuer = claimspkg.DefaultIssuer
	}

	iterator := token.Iterate(ctx)
	for iterator.Next(ctx) {
		pair := iterator.Pair()
		if pair == nil {
			continue
		}

		key := pair.Key
		value := pair.Value

		if !utils.Contains(filter, key.(string)) {
			switch v := value.(type) {
			case []any:
				for _, vv := range v {
					claims = append(claims, claimspkg.NewClaim(
						claimspkg.WithClaimType(key.(string)),
						claimspkg.WithClaimValue(vv),
						claimspkg.WithClaimIssuer(issuer.(string)),
						claimspkg.WithClaimOriginalIssuer(issuer.(string)),
					))
				}
				continue
			}

			claims = append(claims, claimspkg.NewClaim(
				claimspkg.WithClaimType(key.(string)),
				claimspkg.WithClaimValue(value),
				claimspkg.WithClaimIssuer(issuer.(string)),
				claimspkg.WithClaimOriginalIssuer(issuer.(string)),
			))
		}
	}

	return claims
}
