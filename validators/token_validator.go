// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"context"

	"github.com/gonewx/wicket/validators/models"
)

// / TokenValidator Interface for the token validator
type TokenValidator interface {
	/// Validates an access token.
	/// error reports an infrastructure failure; protocol outcomes live in the result.
	ValidateAccessToken(ctx context.Context, token string, expectedScope string) (*models.TokenValidationResult, error)

	/// Validates an identity token.
	/// validateLifetime if set to <c>true</c> the lifetime gets validated. Otherwise not.
	/// error reports an infrastructure failure; protocol outcomes live in the result.
	ValidateIdentityToken(ctx context.Context, token string, clientId string, validateLifetime bool) (*models.TokenValidationResult, error)
}
