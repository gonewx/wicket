// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// Models an error parsing a scope.
type ParsedScopeValidationError struct {
	// The original (raw) value of the scope.
	RawValue string

	// Error message describing why the raw scope failed to be parsed.
	Error error
}
