// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
)

type RemoteEvents[T auth.RemoteOptions[T]] struct {
	OnAccessDenied   func(ctx *authevents.AccessDeniedContext[T]) error
	OnRemoteFailure  func(ctx *authevents.RemoteFailureContext[T]) error
	OnTicketReceived func(ctx *authevents.TicketReceivedContext[T]) error
}

func NewRemoteEvents[T auth.RemoteOptions[T]]() *RemoteEvents[T] {
	return &RemoteEvents[T]{}
}

func (r *RemoteEvents[T]) AccessDenied(ctx *authevents.AccessDeniedContext[T]) error {
	if r.OnAccessDenied != nil {
		return r.OnAccessDenied(ctx)
	}
	return nil
}

func (r *RemoteEvents[T]) RemoteFailure(ctx *authevents.RemoteFailureContext[T]) error {
	if r.OnRemoteFailure != nil {
		return r.OnRemoteFailure(ctx)
	}
	return nil
}

func (r *RemoteEvents[T]) TicketReceived(ctx *authevents.TicketReceivedContext[T]) error {
	if r.OnTicketReceived != nil {
		return r.OnTicketReceived(ctx)
	}
	return nil
}
