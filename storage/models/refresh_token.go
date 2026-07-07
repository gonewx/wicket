// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/claims"
)

// RefreshToken a refresh token.
type RefreshToken struct {
	/// Gets or sets the creation time.
	CreationTime time.Time

	/// Gets or sets the life time.
	Lifetime int

	/// Gets or sets the consumed time.
	ConsumedTime *time.Time

	AccessToken Token

	/// Gets or sets the resource gap specific access token.
	AccessTokens map[string]*Token

	/// Gets or sets the original subject that requested the token.
	Subject *claims.ClaimsPrincipal

	/// Gets or sets the version number.
	Version int

	/// Gets the client identifier.
	ClientId string

	/// Gets the session identifier.
	SessionId string

	/// Gets the description the user assigned to the device being authorized.
	Description string

	/// Gets the scopes.
	AuthorizedScopes []string

	/// The resource gaps. Null indicates there was no authorization step, thus no restrictions.
	/// Non-null means there was an authorization step, and subsequent requested resource gaps must be in the original list.
	AuthorizedResourceGaps []string
}

func NewRefreshToken() *RefreshToken {
	return &RefreshToken{
		AccessTokens: make(map[string]*Token),
		Version:      5,
	}
}

// Returns the access token based on the resource gap.
// / <param name="resourceIndicator"></param>
// / <returns></returns>
func (t *RefreshToken) GetAccessToken(resourceIndicator string) *Token {
	return t.AccessTokens[resourceIndicator]
}

// / Sets the access token based on the resource gap.
// / <param name="resourceIndicator"></param>
// / <param name="token"></param>
// / <returns></returns>
func (t *RefreshToken) SetAccessToken(token *Token, resourceIndicator string) {
	t.AccessTokens[resourceIndicator] = token
}

// / Gets the subject identifier.
func (t *RefreshToken) SubjectId() string {
	if t.Subject == nil {
		return ""
	}

	first := t.Subject.FindFirst(gois.JwtClaimTypesSubject)
	if first == nil {
		return ""
	}

	subjectId, ok := first.Value.(string)
	if !ok {
		return ""
	}
	return subjectId
}
