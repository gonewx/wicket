// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

// HandleRequestContext Base context type for handling authentication request.
type HandleRequestContext[T auth.SchemeOptions[T]] struct {
	*BaseContext[T]

	Result *auth.HandleRequestResult
}

// NewHandleRequestContext Initializes a new instance
func NewHandleRequestContext[T auth.SchemeOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
) *HandleRequestContext[T] {
	return &HandleRequestContext[T]{
		BaseContext: NewBaseContext(r, w, scheme, options),
	}
}

// HandleResponse Discontinue all processing for this request and return to the client.
// The caller is responsible for generating the full response.
func (hrc *HandleRequestContext[T]) HandleResponse() {
	hrc.Result = auth.Handle()
}

// SkipHandler Discontinue processing the request in the current handler.
func (hrc *HandleRequestContext[T]) SkipHandler() {
	hrc.Result = auth.SkipHandler()
}
