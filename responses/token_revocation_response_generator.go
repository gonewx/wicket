// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package responses

import (
	"context"

	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// TokenRevocationResponseGenerator Interface for the revocation response generator
type TokenRevocationResponseGenerator interface {
	// Processes the response.
	Handle(ctx context.Context, validationResult *validators_models.TokenRevocationRequestValidationResult) (*responses_models.TokenRevocationResponse, error)
}
