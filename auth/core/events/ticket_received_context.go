// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

type TicketReceivedContext[T auth.RemoteOptions[T]] struct {
	*RemoteContext[T]

	// Gets or sets the URL to redirect to after signin.
	ReturnUri string
}

func NewTicketReceivedContext[T auth.RemoteOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
	ticket *auth.Ticket,
) *TicketReceivedContext[T] {
	c := &TicketReceivedContext[T]{
		RemoteContext: NewRemoteContext(r, w, scheme, options, ticket.Properties),
	}

	c.RemoteContext.Principal = ticket.Principal

	return c
}
