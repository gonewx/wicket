// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
)

// RemoteContext Base context for remote authentication.
type RemoteContext[T auth.SchemeOptions[T]] struct {
	*HandleRequestContext[T]

	Principal  *claims.ClaimsPrincipal
	Properties *auth.Properties
}

func NewRemoteContext[T auth.SchemeOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
	properties *auth.Properties,
) *RemoteContext[T] {
	if properties == nil {
		properties = auth.NewProperties()
	}
	return &RemoteContext[T]{
		HandleRequestContext: NewHandleRequestContext(r, w, scheme, options),
		Properties:           properties,
	}
}

// Success Calls success creating a ticket with the Principal and Properties
func (c *RemoteContext[T]) Success() {
	c.Result = auth.HandleRequestSuccess(auth.NewTicket(c.Principal, c.Scheme.Name, c.Properties))
}

// Fail Indicates that authentication failed
func (c *RemoteContext[T]) Fail(err error) {
	c.Result = auth.HandleRequestFail(err, nil)
}
