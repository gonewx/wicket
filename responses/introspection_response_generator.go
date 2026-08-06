// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package responses

import (
	"context"

	validators_models "github.com/gonewx/wicket/validators/models"
)

// IntrospectionResponseGenerator Interface introspection response generator
type IntrospectionResponseGenerator interface {
	// Handle the response.
	Handle(ctx context.Context, validationResult *validators_models.IntrospectionRequestValidationResult) map[string]any
}
