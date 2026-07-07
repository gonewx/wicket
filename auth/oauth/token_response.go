// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package oauth

import "github.com/tidwall/gjson"

type TokenResponse struct {
	// Gets or sets the received JSON payload.
	Response string

	// Gets or sets the access token issued by the OAuth provider.
	AccessToken string

	// Gets or sets the token type.
	// <remarks>
	// Typically the string “bearer”.
	// </remarks>
	TokenType string

	// Gets or sets a refresh token that applications can use to obtain another access token if tokens can expire.
	RefreshToken string

	// Gets or sets the validatity lifetime of the token in seconds.
	ExpiresIn string

	// The exception in the event the response was a failure.
	Error error
}

func NewTokenResponse(response string) *TokenResponse {
	accessToken := gjson.Get(response, "access_token").String()
	tokenType := gjson.Get(response, "token_type").String()
	refreshToken := gjson.Get(response, "refresh_token").String()
	expiresIn := gjson.Get(response, "expires_in").String()

	return &TokenResponse{
		Response:     response,
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
	}
}

func NewTokenResponseWithError(err error) *TokenResponse {
	return &TokenResponse{
		Error: err,
	}
}

func Success(response string) *TokenResponse {
	return NewTokenResponse(response)
}

func Failed(err error) *TokenResponse {
	return NewTokenResponseWithError(err)
}
