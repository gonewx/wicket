// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package common

import (
	"github.com/gonewx/wicket/auth"
)

var _ auth.SchemeProvider = (*MockAuthenticationSchemeProvider)(nil)

type MockAuthenticationSchemeProvider struct {
	Default string
	Schemes []*auth.Scheme
}

func NewMockAuthenticationSchemeProvider() *MockAuthenticationSchemeProvider {
	s := auth.NewScheme("scheme", "")

	return &MockAuthenticationSchemeProvider{
		Default: "scheme",
		Schemes: []*auth.Scheme{s},
	}
}

func (p *MockAuthenticationSchemeProvider) GetAllSchemes() []*auth.Scheme {
	return p.Schemes
}
func (p *MockAuthenticationSchemeProvider) GetScheme(name string) *auth.Scheme {
	for _, s := range p.Schemes {
		if s.Name == name {
			return s
		}
	}

	return nil
}
func (p *MockAuthenticationSchemeProvider) GetDefaultAuthenticateScheme() *auth.Scheme {
	return p.GetScheme(p.Default)
}
func (p *MockAuthenticationSchemeProvider) GetDefaultChallengeScheme() *auth.Scheme {
	return p.GetDefaultAuthenticateScheme()
}
func (p *MockAuthenticationSchemeProvider) GetDefaultForbidScheme() *auth.Scheme {
	return p.GetDefaultAuthenticateScheme()
}
func (p *MockAuthenticationSchemeProvider) GetDefaultSignInScheme() *auth.Scheme {
	return p.GetDefaultAuthenticateScheme()
}
func (p *MockAuthenticationSchemeProvider) GetDefaultSignOutScheme() *auth.Scheme {
	return p.GetDefaultAuthenticateScheme()
}
func (p *MockAuthenticationSchemeProvider) AddScheme(scheme *auth.Scheme) error {
	p.Schemes = append(p.Schemes, scheme)
	return nil
}
func (p *MockAuthenticationSchemeProvider) TryAddScheme(scheme *auth.Scheme) bool {
	_ = p.AddScheme(scheme)
	return true
}
func (p *MockAuthenticationSchemeProvider) RemoveScheme(name string) bool {
	for i, s := range p.Schemes {
		if s.Name == name {
			p.Schemes = append(p.Schemes[:i], p.Schemes[i+1:]...)
			return true
		}
	}
	return false
}
func (p *MockAuthenticationSchemeProvider) GetRequestHandlerSchemes() ([]*auth.Scheme, error) {
	return p.Schemes, nil
}
