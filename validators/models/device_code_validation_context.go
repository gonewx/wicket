// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// DeviceCodeValidationContext Validation result for device code validation request.
type DeviceCodeValidationContext struct {
	// Gets or sets the device code.
	// The device code.
	DeviceCode string

	// Gets or sets the request.
	// The request.
	Request *ValidatedTokenRequest

	// Gets or sets the result.
	// The result.
	Result *TokenRequestValidationResult
}
