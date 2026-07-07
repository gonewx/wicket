// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/utils"
)

type Token struct {
	jwt.Token

	// AllowedSigningAlgorithms A list of allowed algorithm for signing the token. If null or empty, will use the default algorithm.
	AllowedSigningAlgorithms []string

	// Confirmation Specifies the confirmation method of the token. This value, if set, will become the cnf claim.
	Confirmation string

	Audiences       []string
	Issuer          string
	CreationTime    time.Time
	Lifetime        int
	Type            string
	ClientId        string
	AccessTokenType gois.AccessTokenType

	// Description Gets the description the user assigned to the device being authorized.
	Description string

	// IncludeJwtId Indicates if the token should have a 'jti' claim value.
	IncludeJwtId bool

	Claims  []*claims.Claim
	Version int
}

// SubjectId Gets the subject identifier.
func (t *Token) SubjectId() string {
	return utils.SingleOrDefault(
		utils.Select(
			utils.Where(t.Claims, func(x *claims.Claim) bool { return x.Type == gois.JwtClaimTypesSubject }),
			func(y *claims.Claim) string {
				if v, ok := y.Value.(string); ok {
					return v
				} else {
					return ""
				}
			},
		),
	)
}

// SessionId Gets the session identifier.
func (t *Token) SessionId() string {
	return utils.SingleOrDefault(
		utils.Select(
			utils.Where(t.Claims, func(x *claims.Claim) bool { return x.Type == gois.JwtClaimTypesSessionId }),
			func(y *claims.Claim) string {
				if v, ok := y.Value.(string); ok {
					return v
				} else {
					return ""
				}
			},
		),
	)
}

// Scopes Gets the scopes.
func (t *Token) Scopes() []string {
	return utils.Select(
		utils.Where(t.Claims, func(x *claims.Claim) bool { return x.Type == gois.JwtClaimTypesScope }),
		func(y *claims.Claim) string {
			if v, ok := y.Value.(string); ok {
				return v
			} else {
				return ""
			}
		},
	)
}
