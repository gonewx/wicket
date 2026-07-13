// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"net/http"

	authcore "github.com/gonewx/wicket/auth/core"
	authevents "github.com/gonewx/wicket/auth/core/events"
	"github.com/gonewx/wicket/auth/oauth"
)

type Events[T oauth.Options[T]] struct {
	*authcore.RemoteEvents[T]

	OnCreatingTicket                  func(ctx *CreatingTicketContext[T]) error
	OnRedirectToAuthorizationEndpoint func(ctx *authevents.RedirectContext[T]) error
}

func NewEvents[T oauth.Options[T]]() *Events[T] {
	return &Events[T]{
		RemoteEvents: authcore.NewRemoteEvents[T](),
		OnCreatingTicket: func(ctx *CreatingTicketContext[T]) error {
			return nil
		},
		OnRedirectToAuthorizationEndpoint: func(ctx *authevents.RedirectContext[T]) error {
			http.Redirect(ctx.Response, ctx.Request, ctx.RedirectUri, http.StatusFound)
			return nil
		},
	}
}

func (r *Events[T]) CreatingTicket(ctx *CreatingTicketContext[T]) error {
	if r.OnCreatingTicket != nil {
		return r.OnCreatingTicket(ctx)
	}
	return nil
}

func (r *Events[T]) RedirectToAuthorizationEndpoint(ctx *authevents.RedirectContext[T]) error {
	if r.OnRedirectToAuthorizationEndpoint != nil {
		return r.OnRedirectToAuthorizationEndpoint(ctx)
	}
	return nil
}
