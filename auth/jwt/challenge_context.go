// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package jwt

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
)

type ChallengeContext struct {
	*authevents.PropertiesContext[*Options]

	Error            error
	ErrorDescription string
	ErrorUri         string
	Handled          bool
}

func NewChallengeContext(
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options *Options,
	properties *auth.Properties,
) *ChallengeContext {
	return &ChallengeContext{
		PropertiesContext: authevents.NewPropertiesContext(r, w, scheme, options, properties),
	}
}

func (c *ChallengeContext) HandleResponse() {
	c.Handled = true
}
