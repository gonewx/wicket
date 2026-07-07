// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// TokenRevocationResponse Models a token revocation response
type TokenRevocationResponse struct {
	// Gets or sets a value indicating whether the token revocation was successful.
	Success bool

	// Gets or sets the type of the token that was revoked.
	TokenType string

	// Gets or sets an error (if present).
	Error error
}
