// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package client

const (
	AuthorizeResponseCode             = "code"
	AuthorizeResponseAccessToken      = "access_token"
	AuthorizeResponseIdentityToken    = "id_token"
	AuthorizeResponseError            = "error"
	AuthorizeResponseErrorDescription = "error_description"
	AuthorizeResponseScope            = "scope"
	AuthorizeResponseTokenType        = "token_type"
	AuthorizeResponseState            = "state"
	AuthorizeResponseSessionState     = "session_state"
	AuthorizeResponseIssuer           = "iss"
	AuthorizeResponseExpiresIn        = "expires_in"

	TokenResponseAccessToken      = "access_token"
	TokenResponseIdentityToken    = "id_token"
	TokenResponseScope            = "scope"
	TokenResponseIssuedTokenType  = "issued_token_type"
	TokenResponseTokenType        = "token_type"
	TokenResponseRefreshToken     = "refresh_token"
	TokenResponseErrorDescription = "error_description"
	TokenResponseExpiresIn        = "expires_in"
)
