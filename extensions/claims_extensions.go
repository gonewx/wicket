// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package extensions

import (
	claimspkg "github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/utils"
)

func ToClaimsMap(claims []*claimspkg.Claim) map[string]any {
	m := make(map[string]any, 0)

	if len(claims) == 0 {
		return m
	}

	distinctClaims := utils.DistinctEq[*claimspkg.Claim](claims, claimspkg.NewClaimComparer())

	for _, claim := range distinctClaims {
		if value, ok := m[claim.Type]; !ok {
			m[claim.Type] = claim.Value
		} else {
			switch v := value.(type) {
			case []any:
				m[claim.Type] = append(v, claim.Value)
			default:
				delete(m, claim.Type)
				m[claim.Type] = []any{v, claim.Value}
			}

		}
	}

	return m
}
