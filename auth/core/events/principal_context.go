// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
)

type PrincipalContext[T auth.SchemeOptions[T]] struct {
	*PropertiesContext[T]

	Principal *claims.ClaimsPrincipal
}

func NewPrincipalContext[T auth.SchemeOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
	properties *auth.Properties,
) *PrincipalContext[T] {
	return &PrincipalContext[T]{
		PropertiesContext: NewPropertiesContext(r, w, scheme, options, properties),
	}
}
