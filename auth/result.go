// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package auth

func NewResult() *Result {
	return &Result{}
}

func Success(ticket *Ticket) *Result {
	return &Result{
		Ticket:     ticket,
		Principal:  ticket.Principal,
		Properties: ticket.Properties,
	}
}

func Fail(err error) *Result {
	return &Result{Failure: err}
}
