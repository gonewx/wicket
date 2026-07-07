// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package tokens

import claimspkg "github.com/gonewx/wicket/claims"

type TokenValidationResult struct {
	IsValid        bool
	Error          error
	ClaimsIdentity *claimspkg.ClaimsIdentity
	Issuer         string
	SecurityToken  SecurityToken
	TokenType      string
}

func NewTokenValidationResult() *TokenValidationResult {
	return &TokenValidationResult{}
}

func (r *TokenValidationResult) Claims() map[string]any {
	if r.ClaimsIdentity == nil {
		return make(map[string]any)
	}

	return createDictionaryFromClaims(r.ClaimsIdentity.Claims())
}

// Creates a dictionary from a list of Claim's.
func createDictionaryFromClaims(claims []*claimspkg.Claim) map[string]any {
	dictionary := make(map[string]any)

	if len(claims) == 0 {
		return dictionary
	}

	for _, claim := range claims {
		if claim == nil {
			continue
		}

		// If there is an existing value, append to it.
		if existingValue, ok := dictionary[claim.Type]; ok {
			if existingValue, arrtype := existingValue.([]any); arrtype {
				dictionary[claim.Type] = append(existingValue, claim.Value)
			} else {
				dictionary[claim.Type] = []any{existingValue, claim.Value}
			}
		} else {
			dictionary[claim.Type] = claim.Value
		}
	}

	return dictionary
}
