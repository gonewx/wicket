// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package oauth

import "github.com/gonewx/wicket/claims"

type ClaimAction interface {
	Run(userData string, identity *claims.ClaimsIdentity, issuer string)
	Typ() string
}
