// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package jwt

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
)

type TokenValidatedContext struct {
	*authevents.ResultContext[*Options]

	/// Bearer Token. This will give the application an opportunity to retrieve a token from an alternative location.
	SecurityToken SecurityToken
}

func NewTokenValidatedContext(
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options *Options,
) *TokenValidatedContext {
	return &TokenValidatedContext{
		ResultContext: authevents.NewResultContext(r, w, scheme, options),
	}
}

func (c *TokenValidatedContext) SetSecurityToken(token SecurityToken) {
	c.SecurityToken = token
}
