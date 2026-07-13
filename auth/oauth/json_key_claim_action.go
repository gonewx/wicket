// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package oauth

import (
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket/claims"
)

// JsonKeyClaimAction A ClaimAction that selects a top level value from the json user data with the given key name and adds it as a Claim.
// This no-ops if the key is not found or the value is empty.
type JsonKeyClaimAction struct {
	ClaimType string
	JsonKey   string
}

func NewJsonKeyClaimAction(claimType string, jsonKey string) *JsonKeyClaimAction {
	return &JsonKeyClaimAction{
		ClaimType: claimType,
		JsonKey:   jsonKey,
	}
}

func (dca *JsonKeyClaimAction) Run(userData string, identity *claims.ClaimsIdentity, issuer string) {
	result := gjson.Get(userData, dca.JsonKey)
	if !result.Exists() {
		return
	}

	value := result.Value()
	switch value := value.(type) {
	case []any:
		for _, v := range value {
			dca.addClaim(v, identity, issuer)
		}
	case string:
		dca.addClaim(value, identity, issuer)
	default:
		// Skip, because they were previously skipped
	}
}

func (dca *JsonKeyClaimAction) Typ() string {
	return dca.ClaimType
}

func (dca *JsonKeyClaimAction) addClaim(value any, identity *claims.ClaimsIdentity, issuer string) {
	identity.AddClaim(claims.NewClaim(
		claims.WithClaimType(dca.ClaimType),
		claims.WithClaimValue(value),
		claims.WithClaimIssuer(issuer),
	))
}
