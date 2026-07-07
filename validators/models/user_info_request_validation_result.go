// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "github.com/gonewx/wicket/claims"

// UserInfoRequestValidationResult Validation result for userinfo requests
type UserInfoRequestValidationResult struct {
	*ValidationResult

	// Gets or sets the token type hint.
	TokenValidationResult *TokenValidationResult

	/// Gets or sets the token.
	Subject *claims.ClaimsPrincipal
}

// Initializes a new instance
func NewUserInfoRequestValidationResult() *UserInfoRequestValidationResult {
	r := &UserInfoRequestValidationResult{
		ValidationResult: NewValidationResult(),
	}
	return r
}
