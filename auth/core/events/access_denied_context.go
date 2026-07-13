// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

type AccessDeniedContext[T auth.RemoteOptions[T]] struct {
	*HandleRequestContext[T]

	// Gets or sets the endpoint path the user agent will be redirected to.
	// By default, this property is set to AccessDeniedPath
	AccessDeniedPath string

	// Additional state values for the authentication session.
	Properties *auth.Properties

	// Gets or sets the return URL that will be flowed up to the access denied page.
	// If ReturnUrlParameter is not set, this property is not used.
	ReturnUrl string

	// Gets or sets the parameter name that will be used to flow the return URL.
	// By default, this property is set to ReturnUrlParameter
	ReturnUrlParameter string
}

func NewAccessDeniedContext[T auth.RemoteOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
) *AccessDeniedContext[T] {
	return &AccessDeniedContext[T]{
		HandleRequestContext: NewHandleRequestContext[T](r, w, scheme, options),
	}
}
