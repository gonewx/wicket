// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/utils"
)

// GrantValidationResult the result of custom grant validation.
type GrantValidationResult struct {
	*ValidationResult
	/// Gets or sets the principal which represents the result of the validation.
	Subject *claims.ClaimsPrincipal

	/// Custom fields for the token response
	CustomResponse map[string]any
}

func WithGrantValidationResultPrincipal(principal *claims.ClaimsPrincipal) gois.Option[GrantValidationResult] {
	return func(r *GrantValidationResult) {
		r.Subject = principal
	}
}

func WithGrantValidationResultError(err gois.TokenRequestErrors, desc string) gois.Option[GrantValidationResult] {
	return func(r *GrantValidationResult) {
		r.Error = convertTokenErrorEnum(err)
		r.Description = desc
	}
}

func WithGrantValidationResultCustomResponse(customResponse map[string]any) gois.Option[GrantValidationResult] {
	return func(r *GrantValidationResult) {
		r.CustomResponse = customResponse
	}
}

func WithGrantValidationResultSubject(subject, authenticationMethod string, authTime time.Time, claims []*claimspkg.Claim, identtityProvider string, customResponse map[string]any) gois.Option[GrantValidationResult] {
	return func(r *GrantValidationResult) {
		resultClaims := []*claimspkg.Claim{
			claimspkg.NewClaim(
				claimspkg.WithClaimType(gois.JwtClaimTypesSubject),
				claimspkg.WithClaimValue(subject),
			),
			claimspkg.NewClaim(
				claimspkg.WithClaimType(gois.JwtClaimTypesAuthenticationMethod),
				claimspkg.WithClaimValue(authenticationMethod),
			),
			claimspkg.NewClaim(
				claimspkg.WithClaimType(gois.JwtClaimTypesIdentityProvider),
				claimspkg.WithClaimValue(identtityProvider),
			),
			claimspkg.NewClaim(
				claimspkg.WithClaimType(gois.JwtClaimTypesAuthenticationTime),
				claimspkg.WithClaimValue(authTime.Unix()),
			),
		}

		if len(claims) > 0 {
			resultClaims = append(resultClaims, claims...)
		}

		id := claimspkg.NewClaimsIdentity(
			claimspkg.WithAuthenticationType(authenticationMethod),
		)

		for _, claim := range utils.DistinctEq[*claimspkg.Claim](resultClaims, claimspkg.NewClaimComparer()) {
			id.AddClaim(claim)
		}

		r.Subject = claimspkg.NewClaimsPrincipal(
			claimspkg.WithClaimsPrincipalIdentity(id),
		)

		r.CustomResponse = customResponse
	}

}
func NewGrantValidationResult(opts ...gois.Option[GrantValidationResult]) *GrantValidationResult {
	r := &GrantValidationResult{
		ValidationResult: NewValidationResult(),
	}

	for _, opt := range opts {
		opt(r)
	}
	return r
}

func convertTokenErrorEnum(err gois.TokenRequestErrors) error {
	switch err {
	case gois.TokenRequestErrorsInvalidClient:
		return gois.TokenErrorsInvalidClient
	case gois.TokenRequestErrorsInvalidGrant:
		return gois.TokenErrorsInvalidGrant
	case gois.TokenRequestErrorsInvalidRequest:
		return gois.TokenErrorsInvalidRequest
	case gois.TokenRequestErrorsInvalidScope:
		return gois.TokenErrorsInvalidScope
	case gois.TokenRequestErrorsUnauthorizedClient:
		return gois.TokenErrorsUnauthorizedClient
	case gois.TokenRequestErrorsUnsupportedGrantType:
		return gois.TokenErrorsUnsupportedGrantType
	case gois.TokenRequestErrorsInvalidTarget:
		return gois.TokenErrorsInvalidTarget
	}
	return nil
}
