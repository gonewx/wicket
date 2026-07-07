// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"github.com/gonewx/wicket/validators/models"
)

// UserInfoRequestValidator Interface for the userinfo request
type UserInfoRequestValidator interface {
	// Validates a userinfo request.
	ValidateRequest(accessToken string) *models.UserInfoRequestValidationResult
}
