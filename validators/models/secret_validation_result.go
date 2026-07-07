// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// SecretValidationResult Validation result for secrets
type SecretValidationResult struct {
	*ValidationResult

	// Gets or sets a value indicating whether the secret validation was successful.
	Success bool

	// Gets or sets the value of the confirmation method (will become the cnf claim). Must be a JSON object.
	Confirmation string
}
