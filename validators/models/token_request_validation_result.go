// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import "github.com/gonewx/wicket"

// TokenRequestValidationResult Validation result for token requests
type TokenRequestValidationResult struct {
	*ValidationResult

	// Gets the validated request.
	ValidatedRequest *ValidatedTokenRequest

	// Gets or sets the custom response.
	CustomResponse map[string]any
}

func WithTokenRequestValidationResultCustomResponse(customResponse map[string]any) gois.Option[TokenRequestValidationResult] {
	return func(r *TokenRequestValidationResult) {
		r.CustomResponse = customResponse
	}
}

func WithTokenRequestValidationResultError(err error) gois.Option[TokenRequestValidationResult] {
	return func(r *TokenRequestValidationResult) {
		r.Error = err
	}
}

func WithTokenRequestValidationResultDescription(description string) gois.Option[TokenRequestValidationResult] {
	return func(r *TokenRequestValidationResult) {
		r.Description = description
	}
}

// Initializes a new instance
func NewTokenRequestValidationResult(validatedRequest *ValidatedTokenRequest, opts ...gois.Option[TokenRequestValidationResult]) *TokenRequestValidationResult {
	r := &TokenRequestValidationResult{
		ValidationResult: NewValidationResult(),
		ValidatedRequest: validatedRequest,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}
