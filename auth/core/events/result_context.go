// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package events

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
)

// Base context for authentication events which contain Properties".
type ResultContext[T auth.SchemeOptions[T]] struct {
	*BaseContext[T]

	properties *auth.Properties
	Result     *auth.Result
	Principal  *claims.ClaimsPrincipal
}

func NewResultContext[T auth.SchemeOptions[T]](
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
) *ResultContext[T] {
	return &ResultContext[T]{
		BaseContext: NewBaseContext(r, w, scheme, options),
	}
}

func (c *ResultContext[T]) Properties() *auth.Properties {
	if c.properties == nil {
		c.properties = auth.NewProperties()
	}

	return c.properties
}

func (c *ResultContext[T]) SetProperties(properties *auth.Properties) {
	c.properties = properties
}

// Calls success creating a ticket with the Principal and Properties
func (c *ResultContext[T]) Success() {
	c.Result = auth.Success(auth.NewTicket(c.Principal, c.Scheme.Name, c.Properties()))
}

// Indicates that there was no information returned for this authentication scheme.
func (c *ResultContext[T]) NoResult() {
	c.Result = auth.NoResult()
}

// Indicates that there was a failure during authentication.
func (c *ResultContext[T]) Fail(err error) {
	c.Result = auth.Fail(err)
}
