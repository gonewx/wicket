// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "github.com/gonewx/wicket"

// DeviceAuthorizationRequestValidationResult Validation result for device authorization requests
type DeviceAuthorizationRequestValidationResult struct {
	*ValidationResult

	// Gets the validated request.
	ValidatedRequest *ValidatedDeviceAuthorizationRequest
}

func WithDeviceAuthorizationRequestValidationResultError(err error) gois.Option[DeviceAuthorizationRequestValidationResult] {
	return func(r *DeviceAuthorizationRequestValidationResult) {
		r.Error = err
	}
}

func WithDeviceAuthorizationRequestValidationResultDescription(description string) gois.Option[DeviceAuthorizationRequestValidationResult] {
	return func(r *DeviceAuthorizationRequestValidationResult) {
		r.Description = description
	}
}

// Initializes a new instance
func NewDeviceAuthorizationRequestValidationResult(validatedRequest *ValidatedDeviceAuthorizationRequest, opts ...gois.Option[DeviceAuthorizationRequestValidationResult]) *DeviceAuthorizationRequestValidationResult {
	r := &DeviceAuthorizationRequestValidationResult{
		ValidationResult: NewValidationResult(),
		ValidatedRequest: validatedRequest,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}
