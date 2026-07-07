// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package services

import "github.com/gonewx/wicket/models/messages"

// ReturnUrlParser Interface for the return URL parser
type ReturnUrlParser interface {
	// Parses a return URL.
	Parse(returnUrl string) (*messages.AuthorizationRequest, error)
	// Determines whether the return URL is valid.
	IsValidReturnUrl(returnUrl string) bool
}
