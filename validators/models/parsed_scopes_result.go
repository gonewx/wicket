// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type ParsedScopesResult struct {
	// The valid parsed scopes.
	ParsedScopes []*ParsedScopeValue

	// The errors encountered while parsing.
	Errors []*ParsedScopeValidationError
}

// Indicates if the result of parsing the scopes was successful.
func (r *ParsedScopesResult) Succeeded() bool {
	return len(r.Errors) == 0
}
