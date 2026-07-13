// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package oauth

import "github.com/gonewx/wicket/claims"

// DeleteClaimAction A ClaimAction that deletes all claims from the given ClaimsIdentity with the given ClaimType.
type DeleteClaimAction struct {
	ClaimType string
}

func NewDeleteClaimAction(claimType string) *DeleteClaimAction {
	return &DeleteClaimAction{
		ClaimType: claimType,
	}
}

func (dca *DeleteClaimAction) Run(userData string, identity *claims.ClaimsIdentity, issuer string) {
	for _, claim := range identity.FindAll(dca.ClaimType) {
		identity.TryRemoveClaim(claim)
	}
}

func (dca *DeleteClaimAction) Typ() string {
	return dca.ClaimType
}
