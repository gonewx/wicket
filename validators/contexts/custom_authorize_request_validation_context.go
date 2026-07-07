// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators_contexts

import validators_models "github.com/gonewx/wicket/validators/models"

// Context for custom authorize request validation.
type CustomAuthorizeRequestValidationContext struct {
	// The result of custom validation.
	Request *validators_models.ValidatedAuthorizeRequest
}
