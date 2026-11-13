// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/gonewx/wicket"
	claimspkg "github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/utils"
)

func CreateJwtPayload(token *storage_models.Token, options *config_options.WicketOptions, clock services.SystemClock, logger *slog.Logger) (jwt.Token, error) {

	payload := jwt.New()
	if err := payload.Set(wicket.JwtClaimTypesIssuer, token.Issuer); err != nil {
		return nil, err
	}

	// set times (nbf, exp, iat)
	now := clock.Now().Unix()
	exp := now + int64(token.Lifetime)

	if err := payload.Set(wicket.JwtClaimTypesNotBefore, now); err != nil {
		return nil, err
	}
	if err := payload.Set(wicket.JwtClaimTypesIssuedAt, now); err != nil {
		return nil, err
	}
	if err := payload.Set(wicket.JwtClaimTypesExpiration, exp); err != nil {
		return nil, err
	}

	// add audience claim(s)
	count := len(token.Audiences)
	if count > 0 {
		if count == 1 {
			if err := payload.Set(wicket.JwtClaimTypesAudience, token.Audiences[0]); err != nil {
				return nil, err
			}
		} else {
			if err := payload.Set(wicket.JwtClaimTypesAudience, token.Audiences); err != nil {
				return nil, err
			}
		}
	}

	// add confirmation claim (if present)
	if strings.TrimSpace(token.Confirmation) != "" {
		var confirmation any
		err := json.Unmarshal([]byte(token.Confirmation), &confirmation)
		if err != nil {
			return nil, err
		}
		if err := payload.Set(wicket.JwtClaimTypesConfirmation, confirmation); err != nil {
			return nil, err
		}
	}

	// scope claims.
	scopeClaims := utils.Where(token.Claims, func(x *claimspkg.Claim) bool { return x.Type == wicket.JwtClaimTypesScope })
	if len(scopeClaims) > 0 {
		scopeValues := utils.Select(scopeClaims, func(x *claimspkg.Claim) string { return x.Value.(string) })

		if options.EmitScopesAsSpaceDelimitedStringInJwt {
			if err := payload.Set(wicket.JwtClaimTypesScope, strings.Join(scopeValues, " ")); err != nil {
				return nil, err
			}
		} else {
			if err := payload.Set(wicket.JwtClaimTypesScope, scopeValues); err != nil {
				return nil, err
			}
		}
	}

	// amr claims.
	amrClaims := utils.Where(token.Claims, func(x *claimspkg.Claim) bool { return x.Type == wicket.JwtClaimTypesAuthenticationMethod })
	if len(amrClaims) > 0 {
		amrValues := utils.Distinct(utils.Select(amrClaims, func(x *claimspkg.Claim) string { return x.Value.(string) }))
		if err := payload.Set(wicket.JwtClaimTypesAuthenticationMethod, amrValues); err != nil {
			return nil, err
		}
	}

	simpleClaimTypes := utils.Distinct(
		utils.Select(
			utils.Where(token.Claims, func(c *claimspkg.Claim) bool {
				return c.Type != wicket.JwtClaimTypesAuthenticationMethod && c.Type != wicket.JwtClaimTypesScope
			}), func(c *claimspkg.Claim) string { return c.Type },
		))

	// other claims.
	for _, claimType := range simpleClaimTypes {
		// we ignore claims. that are added by the above code for token verification
		if !payload.Has(claimType) {
			claims := utils.Where(token.Claims, func(c *claimspkg.Claim) bool { return c.Type == claimType })

			if len(claims) > 1 {
				values := make([]any, len(claims))
				for i, claim := range claims {
					values[i] = claim.Value
				}
				if err := payload.Set(claimType, values); err != nil {
					return nil, err
				}
			} else {
				if err := payload.Set(claimType, claims[0].Value); err != nil {
					return nil, err
				}
			}
		}
	}

	return payload, nil
}
