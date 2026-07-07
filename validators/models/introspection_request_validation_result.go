// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

import (
	"net/url"

	"github.com/gonewx/wicket/claims"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// / Validation result for introspection request
// / <seealso cref="ValidationResult" />
type IntrospectionRequestValidationResult struct {
	*ValidationResult
	/// Gets or sets the request parameters.
	Parameters url.Values

	/// Gets or sets the API.
	Api *storage_models.ApiResource

	/// Gets or sets a value indicating whether the token is active.
	IsActive bool

	/// Gets or sets the claims..
	Claims []*claims.Claim

	/// Gets or sets the token.
	Token string
}

func NewIntrospectionRequestValidationResult() *IntrospectionRequestValidationResult {
	return &IntrospectionRequestValidationResult{
		ValidationResult: NewValidationResult(),
	}
}

// / Failure reasons for introspection request
type IntrospectionRequestValidationFailureReason int

const (
	/// none
	None IntrospectionRequestValidationFailureReason = iota

	/// missing token
	MissingToken

	/// invalid token
	InvalidToken

	/// invalid scope
	InvalidScope
)
