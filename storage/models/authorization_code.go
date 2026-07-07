// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"time"

	"github.com/gonewx/wicket/claims"
)

// AuthorizationCode an authorization code.
type AuthorizationCode struct {
	// The creation time.
	CreationTime time.Time

	// Gets or sets the life time in seconds.
	// The life time.
	Lifetime int

	// Gets or sets the ID of the client.
	// The ID of the client.
	ClientId string

	// Gets or sets the subject.
	// The subject.
	Subject *claims.ClaimsPrincipal

	// Gets or sets a value indicating whether this code is an OpenID Connect code.
	// <c>true</c> if this instance is open identifier; otherwise, <c>false</c>.
	IsOpenId bool

	// Gets or sets the requested scopes.
	// The requested scopes.
	// todo: brock, change to parsed scopes
	RequestedScopes []string

	// Gets or sets the requested resource gaps.
	RequestedResourceGaps []string

	// Gets or sets the redirect URI.
	// The redirect URI.
	RedirectUri string

	// Gets or sets the nonce.
	// The nonce.
	Nonce string

	// Gets or sets the hashed state (to output s_hash claim).
	// The hashed state.
	StateHash string

	// Gets or sets a value indicating whether consent was shown.
	//  true if consent was shown; otherwise, false.
	WasConsentShown bool

	// Gets or sets the session identifier.
	// The session identifier.
	SessionId string

	// Gets or sets the code challenge.
	// The code challenge.
	CodeChallenge string

	// Gets or sets the code challenge method.
	// The code challenge method
	CodeChallengeMethod string

	// Gets the description the user assigned to the device being authorized.
	// The description.
	Description string

	// Gets or sets properties
	// The properties
	Properties map[string]string
}

func NewAuthorizationCode() *AuthorizationCode {
	return &AuthorizationCode{
		Properties: make(map[string]string),
	}
}
