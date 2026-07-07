// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package models

// EndSessionCallbackValidationResult Validation result for end session callback requests.
type EndSessionCallbackValidationResult struct {
	*ValidationResult

	// Gets the client front-channel logout urls.
	FrontChannelLogoutUrls []string
}

func NewEndSessionCallbackValidationResult() *EndSessionCallbackValidationResult {
	return &EndSessionCallbackValidationResult{
		ValidationResult: NewValidationResult(),
	}
}
