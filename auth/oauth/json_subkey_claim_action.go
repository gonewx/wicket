// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package oauth

import (
	"fmt"

	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket/claims"
)

// JsonSubKeyClaimAction A ClaimAction that selects a second level value from the json user data with the given top level key
// name and second level sub key name and add it as a Claim.
// This no-ops if the keys are not found or the value is empty.
type JsonSubKeyClaimAction struct {
	*JsonKeyClaimAction

	// The second level key to look for in the json user data.
	SubKey string
}

func NewJsonSubKeyClaimAction(claimType string, jsonKey string, subKey string) *JsonSubKeyClaimAction {
	return &JsonSubKeyClaimAction{
		JsonKeyClaimAction: NewJsonKeyClaimAction(claimType, jsonKey),
		SubKey:             subKey,
	}
}

func (dca *JsonSubKeyClaimAction) Run(userData string, identity *claims.ClaimsIdentity, issuer string) {
	result := gjson.Get(userData, fmt.Sprintf("%s.%s", dca.JsonKey, dca.SubKey))
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

func (dca *JsonSubKeyClaimAction) addClaim(value any, identity *claims.ClaimsIdentity, issuer string) {
	identity.AddClaim(claims.NewClaim(
		claims.WithClaimType(dca.ClaimType),
		claims.WithClaimValue(value),
		claims.WithClaimIssuer(issuer),
	))
}
