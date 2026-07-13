// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

type RedirectContext[T auth.SchemeOptions[T]] struct {
	*PropertiesContext[T]

	/// Gets or Sets the URI used for the redirect operation.
	RedirectUri string
}

func NewRedirectContext[T auth.SchemeOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
	properties *auth.Properties,
	redirectUri string,
) *RedirectContext[T] {
	return &RedirectContext[T]{
		PropertiesContext: NewPropertiesContext(r, w, scheme, options, properties),
		RedirectUri:       redirectUri,
	}
}
