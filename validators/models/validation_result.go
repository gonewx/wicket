// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type ValidationResult struct {
	// a value indicating whether the validation was successful.
	Error error

	// The error description.
	Description string
}

func NewValidationResult() *ValidationResult {
	return &ValidationResult{}
}
