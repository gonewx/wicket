// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package responses

import (
	validators_models "github.com/gonewx/wicket/validators/models"
)

// UserInfoResponseGenerator Interface for the userinfo response generator
type UserInfoResponseGenerator interface {
	// Processes the response.
	Handle(validationResult *validators_models.UserInfoRequestValidationResult) (map[string]any, error)
}
