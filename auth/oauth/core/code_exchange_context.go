// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import "github.com/gonewx/wicket/auth"

// CodeExchangeContext Contains information used to perform the code exchange.
type CodeExchangeContext struct {
	// Properties State for the authentication flow.
	Properties *auth.Properties

	// Code The code returned from the authorization endpoint.
	Code string

	// RedirectUri The redirect uri used in the authorization request.
	RedirectUri string
}

// NewCodeExchangeContext Creates a new instance of the context object.
func NewCodeExchangeContext(properties *auth.Properties, code string, redirectUri string) *CodeExchangeContext {
	return &CodeExchangeContext{
		Properties:  properties,
		Code:        code,
		RedirectUri: redirectUri,
	}
}
