// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators_contexts

import validators_models "github.com/gonewx/wicket/validators/models"

// CustomTokenRequestValidationContext  Context for custom token request validation.
type CustomTokenRequestValidationContext struct {
	// The result of custom validation.
	Result *validators_models.TokenRequestValidationResult
}
