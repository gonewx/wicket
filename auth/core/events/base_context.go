// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

type BaseContext[T auth.SchemeOptions[T]] struct {
	// The authentication scheme.
	Scheme *auth.Scheme

	// Gets the authentication options associated with the scheme.
	Options T

	// The request.
	Request *http.Request

	// The response.
	Response http.ResponseWriter
}

func NewBaseContext[T auth.SchemeOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
) *BaseContext[T] {
	return &BaseContext[T]{
		Request:  r,
		Response: w,
		Scheme:   scheme,
		Options:  options,
	}
}
