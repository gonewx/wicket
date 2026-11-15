// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// TokenResponseTokenType carries the token_type of a token response.
type TokenResponseTokenType struct {
	// TokenType is the token_type written to the response; "" stands for
	// BearerTokenType.
	TokenType string
}
