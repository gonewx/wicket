// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import (
	"net/url"

	"github.com/gonewx/wicket/claims"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// EndSessionRequestValidator  Validates end session requests.
type EndSessionRequestValidator interface {
	// Validates end session endpoint requests.
	Validate(parameters url.Values, subject *claims.ClaimsPrincipal) (*validators_models.EndSessionValidationResult, error)

	//  Validates requests from logout page iframe to trigger single signout.
	ValidateCallback(parameters url.Values) (*validators_models.EndSessionCallbackValidationResult, error)
}
