// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "github.com/gonewx/wicket"

// TokenErrorResponse Models a token error response
type TokenErrorResponse struct {
	Error error

	ErrorDescription string

	// Gets or sets the custom entries.
	Custom map[string]any
}

func NewTokenErrorResponse() *TokenErrorResponse {
	return &TokenErrorResponse{
		Error:  wicket.TokenErrorsInvalidRequest,
		Custom: make(map[string]any),
	}
}
