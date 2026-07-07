// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// Models the validation result of access tokens and id tokens.
type TokenValidationResult struct {
	*ValidationResult

	/// Gets or sets the claims..
	/// The claims..
	Claims []*claims.Claim

	/// Gets or sets the JWT.
	/// The JWT.
	Jwt string

	/// Gets or sets the reference token (in case of access token validation).
	/// The reference token.
	ReferenceToken *storage_models.Token

	/// Gets or sets the reference token identifier (in case of access token validation).
	/// The reference token identifier.
	ReferenceTokenId string

	/// Gets or sets the refresh token (in case of refresh token validation).
	/// The reference token identifier.
	RefreshToken *storage_models.RefreshToken

	/// Gets or sets the client.
	/// The client.
	Client *storage_models.Client

	Subject *claims.ClaimsPrincipal
}

func NewTokenValidationResult() *TokenValidationResult {
	return &TokenValidationResult{
		ValidationResult: NewValidationResult(),
	}
}
