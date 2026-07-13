// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

type RemoteFailureContext[T auth.RemoteOptions[T]] struct {
	*HandleRequestContext[T]

	// User friendly error message for the error.
	Failure error

	// Additional state values for the authentication session.
	Properties *auth.Properties
}

func NewRemoteFailureContext[T auth.RemoteOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
	failure error,
) *RemoteFailureContext[T] {
	return &RemoteFailureContext[T]{
		HandleRequestContext: NewHandleRequestContext(r, w, scheme, options),
		Failure:              failure,
	}
}
