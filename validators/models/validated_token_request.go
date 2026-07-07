// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import storage_models "github.com/gonewx/wicket/storage/models"

// Models a validated request to the token endpoint.
type ValidatedTokenRequest struct {
	*ValidatedRequest

	// Gets or sets the type of the grant.
	GrantType string

	// Gets or sets the scopes.
	RequestedScopes []string

	// Gets or sets the resource gap.
	RequestedResourceGap string

	// Gets or sets the username used in the request.
	UserName string

	// Gets or sets the refresh token.
	RefreshToken *storage_models.RefreshToken

	// Gets or sets the refresh token handle.
	RefreshTokenHandle string

	// Gets or sets the authorization code.
	AuthorizationCode *storage_models.AuthorizationCode

	// Gets or sets the authorization code handle.
	AuthorizationCodeHandle string

	// Gets or sets the code verifier.
	CodeVerifier string

	// Gets or sets the device code.
	DeviceCode *storage_models.DeviceCode

	// Gets or sets the clean-room gap request placeholder.
	CleanRoomGapRequest *storage_models.CleanRoomGapRequest
}

func NewValidatedTokenRequest() *ValidatedTokenRequest {
	return &ValidatedTokenRequest{
		ValidatedRequest: NewValidatedRequest(),
	}
}
