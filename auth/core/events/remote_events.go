// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import "github.com/gonewx/wicket/auth"

type RemoteEvents[T auth.RemoteOptions[T]] interface {
	AccessDenied(ctx *AccessDeniedContext[T]) error
	RemoteFailure(ctx *RemoteFailureContext[T]) error
	TicketReceived(ctx *TicketReceivedContext[T]) error
}
