// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	validators_contexts "github.com/gonewx/wicket/validators/contexts"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type JwtRequestValidator interface {
	Validate(ctx *validators_contexts.JwtRequestValidationContext) (*validators_models.JwtRequestValidationResult, error)
}
