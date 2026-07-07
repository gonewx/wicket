// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"net/http"

	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
)

var _ auth.Service = (*MockAuthenticationService)(nil)

type MockAuthenticationService struct {
	Result *auth.Result
}

func NewMockAuthenticationService() auth.Service {
	return &MockAuthenticationService{}
}

func (s *MockAuthenticationService) Authenticate(request *http.Request, response http.ResponseWriter, scheme string) (*auth.Result, error) {
	return s.Result, nil
}
func (s *MockAuthenticationService) Challenge(request *http.Request, response http.ResponseWriter, scheme string, properties *auth.Properties) error {
	return nil
}
func (s *MockAuthenticationService) Forbid(request *http.Request, response http.ResponseWriter, scheme string, properties *auth.Properties) error {
	return nil
}
func (s *MockAuthenticationService) SignIn(request *http.Request, response http.ResponseWriter, scheme string, principal *claims.ClaimsPrincipal, properties *auth.Properties) error {
	return nil
}
func (s *MockAuthenticationService) SignOut(request *http.Request, response http.ResponseWriter, scheme string, properties *auth.Properties) error {
	return nil
}

func (s *MockAuthenticationService) TryAllRequestHandler(request *http.Request, response http.ResponseWriter) bool {
	return true
}
func (s *MockAuthenticationService) GetDefaultAuthenticateScheme() *auth.Scheme {
	return nil
}

func (s *MockAuthenticationService) Initialize() {
}
