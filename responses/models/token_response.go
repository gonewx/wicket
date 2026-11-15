// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

const (
	AccessToken      = "access_token"
	ExpiresIn        = "expires_in"
	TokenType        = "token_type"
	RefreshToken     = "refresh_token"
	IdentityToken    = "id_token"
	Error            = "error"
	ErrorDescription = "error_description"
	BearerTokenType  = "Bearer"
	IssuedTokenType  = "issued_token_type"
	Scope            = "scope"
)

// TokenResponse Models a token response
type TokenResponse struct {
	// Gets or sets the identity token.
	IdentityToken string

	// Gets or sets the access token.
	AccessToken string

	// Gets or sets the access token lifetime.
	AccessTokenLifetime int

	// Gets or sets the refresh token.
	RefreshToken string

	// Gets or sets the scope.
	Scope string

	// Gets or sets the custom entries.
	Custom map[string]any

	TokenResponseTokenType
}
