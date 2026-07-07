// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package messages

import (
	"github.com/tidwall/gjson"

	"github.com/gonewx/wicket/client"
)

type TokenResponse struct {
	*ProtocolResponse
}

func NewTokenResponse() *TokenResponse {
	return &TokenResponse{
		ProtocolResponse: NewProtocolResponse(),
	}
}

// AccessToken Gets the access token.
func (r *TokenResponse) AccessToken() string {
	return gjson.Get(r.Raw, client.TokenResponseAccessToken).String()
}

// IdentityToken Gets the identity token.
func (r *TokenResponse) IdentityToken() string {
	return gjson.Get(r.Raw, client.TokenResponseIdentityToken).String()
}

func (r *TokenResponse) Scope() string {
	return gjson.Get(r.Raw, client.TokenResponseScope).String()
}

func (r *TokenResponse) IssuedTokenType() string {
	return gjson.Get(r.Raw, client.TokenResponseIssuedTokenType).String()
}

func (r *TokenResponse) TokenType() string {
	return gjson.Get(r.Raw, client.TokenResponseTokenType).String()
}

func (r *TokenResponse) RefreshToken() string {
	return gjson.Get(r.Raw, client.TokenResponseRefreshToken).String()
}

func (r *TokenResponse) ErrorDescription() string {
	return gjson.Get(r.Raw, client.TokenResponseErrorDescription).String()
}

func (r *TokenResponse) ExpiresIn() int {
	return int(gjson.Get(r.Raw, client.TokenResponseExpiresIn).Int())
}
