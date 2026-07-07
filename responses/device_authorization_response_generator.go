// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package responses

import (
	responses_models "github.com/gonewx/wicket/responses/models"
	validators_models "github.com/gonewx/wicket/validators/models"
)

// DeviceAuthorizationResponseGenerator Interface the device authorization response generator
type DeviceAuthorizationResponseGenerator interface {
	// Processes the response.
	Handle(validationResult *validators_models.DeviceAuthorizationRequestValidationResult, baseUrl string) (*responses_models.DeviceAuthorizationResponse, error)
}
