// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// Validation result for end session requests
type AuthorizeRequestValidationResult struct {
	*ValidationResult

	ValidatedRequest *ValidatedAuthorizeRequest
}

func NewAuthorizeRequestValidationResult(request *ValidatedAuthorizeRequest) *AuthorizeRequestValidationResult {
	return NewAuthorizeRequestValidationResultWithErr(request, nil, "")
}

func NewAuthorizeRequestValidationResultWithErr(request *ValidatedAuthorizeRequest, err error, desc string) *AuthorizeRequestValidationResult {
	base := NewValidationResult()
	base.Error = err
	base.Description = desc
	return &AuthorizeRequestValidationResult{
		ValidationResult: base,
		ValidatedRequest: request,
	}
}
