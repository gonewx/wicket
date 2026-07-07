// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package validators

import validators_models "github.com/gonewx/wicket/validators/models"

// DeviceCodeValidator Allows inserting custom validation logic into token requests
type DeviceCodeValidator interface {
	// Custom validation logic for a token request.
	Validate(ctx *validators_models.DeviceCodeValidationContext) error
}
