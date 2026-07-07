// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

var _ auth.Handler = (*MockAuthenticationHandler)(nil)

type MockAuthenticationHandler struct {
	Result *auth.Result
}

func NewMockAuthenticationHandler() *MockAuthenticationHandler {
	return &MockAuthenticationHandler{
		Result: auth.NoResult(),
	}
}

// Initialize the authentication handler. The handler should initialize anything it needs from the request and scheme as part of this method.
func (h *MockAuthenticationHandler) Initialize(request *http.Request, response http.ResponseWriter, scheme *auth.Scheme) error {
	return nil
}

// Authenticate the current request.
func (h *MockAuthenticationHandler) Authenticate() (*auth.Result, error) {
	return h.Result, nil
}

// Challenge the current request.
func (h *MockAuthenticationHandler) Challenge(properties *auth.Properties) error {
	return nil
}

// Forbid the current request.
func (h *MockAuthenticationHandler) Forbid(properties *auth.Properties) error {
	return nil
}
