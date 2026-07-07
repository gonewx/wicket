// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
)

var _ auth.HandlerProvider = (*MockAuthenticationHandlerProvider)(nil)

type MockAuthenticationHandlerProvider struct {
	Handler auth.Handler
}

func NewMockAuthenticationHandlerProvider() *MockAuthenticationHandlerProvider {
	return &MockAuthenticationHandlerProvider{}
}

// Returns the handler instance that will be used.
func (p *MockAuthenticationHandlerProvider) GetHandler(request *http.Request, response http.ResponseWriter, scheme string) (auth.Handler, error) {
	return p.Handler, nil
}
