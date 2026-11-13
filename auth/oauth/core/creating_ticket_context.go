// Copyright (c) .NET Foundation and Contributors. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Modifications Copyright 2026 Decker.

package core

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authevents "github.com/gonewx/wicket/auth/core/events"
	"github.com/gonewx/wicket/auth/oauth"
	"github.com/gonewx/wicket/claims"
)

type CreatingTicketContext[T oauth.Options[T]] struct {
	*authevents.ResultContext[T]

	User string

	TokenResponse *oauth.TokenResponse

	Backchannel *http.Client
}

func NewCreatingTicketContext[T oauth.Options[T]](
	principal *claims.ClaimsPrincipal,
	properties *auth.Properties,
	r *http.Request,
	w http.ResponseWriter,
	scheme *auth.Scheme,
	options T,
	backchannel *http.Client,
	tokens *oauth.TokenResponse,
	user string,
) (*CreatingTicketContext[T], error) {
	if backchannel == nil {
		return nil, wicket.ArgumentNullException
	}
	if tokens == nil {
		return nil, wicket.ArgumentNullException
	}
	c := &CreatingTicketContext[T]{
		ResultContext: authevents.NewResultContext(r, w, scheme, options),
		TokenResponse: tokens,
		Backchannel:   backchannel,
		User:          user,
	}

	c.ResultContext.Principal = principal
	c.ResultContext.SetProperties(properties)

	return c, nil
}

func (c *CreatingTicketContext[T]) AccessToken() string {
	return c.TokenResponse.AccessToken
}

func (c *CreatingTicketContext[T]) TokenType() string {
	return c.TokenResponse.TokenType
}

func (c *CreatingTicketContext[T]) RefreshToken() string {
	return c.TokenResponse.RefreshToken
}

func (c *CreatingTicketContext[T]) ExpiresIn() *time.Duration {
	value, err := strconv.Atoi(c.TokenResponse.ExpiresIn)
	if err != nil {
		return nil
	}

	duration := time.Duration(value) * time.Second
	return &duration
}

func (c *CreatingTicketContext[T]) Identity() *claims.ClaimsIdentity {
	id, ok := c.Principal.Identity().(*claims.ClaimsIdentity)
	if !ok {
		return nil
	}
	return id
}

func (c *CreatingTicketContext[T]) RunClaimActions() {
	c.RunClaimActionsWithData(c.User)
}

func (c *CreatingTicketContext[T]) RunClaimActionsWithData(userData string) {
	for _, action := range c.Options.ClaimActions() {
		issuer := c.Options.ClaimsIssuer()
		if issuer == "" {
			issuer = c.Scheme.Name
		}
		action.Run(userData, c.Identity(), issuer)
	}
}
