// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

type BearerTokenUsageType int

const (
	AuthorizationHeader BearerTokenUsageType = iota
	PostBody
	QueryString
)

// Models usage of a bearer token
type BearerTokenUsageValidationResult struct {
	// Gets or sets a value indicating whether the token was found.
	//   <c>true</c> if the token was found; otherwise, <c>false</c>.
	TokenFound bool

	// Gets or sets the token.
	// The token.
	Token string

	// Gets or sets the usage type.
	// The type of the usage.
	UsageType BearerTokenUsageType
}
