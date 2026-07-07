// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import "github.com/gonewx/wicket/validators/models"

// / TokenValidator Interface for the token validator
type TokenValidator interface {
	/// Validates an access token.
	ValidateAccessToken(token string, expectedScope string) *models.TokenValidationResult

	/// Validates an identity token.
	/// validateLifetime if set to <c>true</c> the lifetime gets validated. Otherwise not.
	ValidateIdentityToken(token string, clientId string, validateLifetime bool) *models.TokenValidationResult
}
