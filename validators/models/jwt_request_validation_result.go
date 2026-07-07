// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"github.com/gonewx/wicket/claims"
)

type JwtRequestValidationResult struct {
	*ValidationResult

	// The key/value pairs from the JWT payload of a successfuly validated request.
	Payload []*claims.Claim
}

func NewJwtRequestValidationResult() *JwtRequestValidationResult {
	return &JwtRequestValidationResult{ValidationResult: NewValidationResult()}
}
