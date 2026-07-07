// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// Validation result for end session requests
type EndSessionValidationResult struct {
	*ValidationResult

	ValidatedRequest *ValidatedEndSessionRequest
}

func NewEndSessionValidationResult() *EndSessionValidationResult {
	return &EndSessionValidationResult{
		ValidationResult: NewValidationResult(),
	}
}
