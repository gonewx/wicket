// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"context"
	"net/url"

	"github.com/gonewx/wicket/claims"
	validators_models "github.com/gonewx/wicket/validators/models"
)

type AuthorizeRequestValidator interface {
	Validate(ctx context.Context, values url.Values, subject *claims.ClaimsPrincipal, phase AuthorizeRequestPhase) *validators_models.AuthorizeRequestValidationResult
}
