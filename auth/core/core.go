// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
)

type SchemeProvider struct {
	schemes []*auth.Scheme
}

func NewSchemeProvider() *SchemeProvider {
	return &SchemeProvider{}
}

func (p *SchemeProvider) GetAllSchemes() []*auth.Scheme {
	return append([]*auth.Scheme(nil), p.schemes...)
}

func (p *SchemeProvider) GetScheme(name string) *auth.Scheme {
	for _, scheme := range p.schemes {
		if scheme.Name == name {
			return scheme
		}
	}
	return nil
}

func (p *SchemeProvider) GetDefaultAuthenticateScheme() *auth.Scheme { return firstScheme(p.schemes) }
func (p *SchemeProvider) GetDefaultChallengeScheme() *auth.Scheme    { return firstScheme(p.schemes) }
func (p *SchemeProvider) GetDefaultForbidScheme() *auth.Scheme       { return firstScheme(p.schemes) }
func (p *SchemeProvider) GetDefaultSignInScheme() *auth.Scheme       { return firstScheme(p.schemes) }
func (p *SchemeProvider) GetDefaultSignOutScheme() *auth.Scheme      { return firstScheme(p.schemes) }

func firstScheme(schemes []*auth.Scheme) *auth.Scheme {
	if len(schemes) == 0 {
		return nil
	}
	return schemes[0]
}

func (p *SchemeProvider) AddScheme(scheme *auth.Scheme) error {
	if scheme == nil {
		return fmt.Errorf("auth scheme is nil")
	}
	if p.GetScheme(scheme.Name) != nil {
		return fmt.Errorf("auth scheme %q already exists", scheme.Name)
	}
	p.schemes = append(p.schemes, scheme)
	return nil
}

func (p *SchemeProvider) TryAddScheme(scheme *auth.Scheme) bool {
	if scheme == nil || p.GetScheme(scheme.Name) != nil {
		return false
	}
	p.schemes = append(p.schemes, scheme)
	return true
}

func (p *SchemeProvider) GetRequestHandlerSchemes() ([]*auth.Scheme, error) {
	return nil, nil
}

type HandlerProvider struct {
	schemes  auth.SchemeProvider
	provider godi.Provider
}

func NewHandlerProvider(schemes auth.SchemeProvider, provider godi.Provider) *HandlerProvider {
	return &HandlerProvider{schemes: schemes, provider: provider}
}

func (p *HandlerProvider) GetHandler(request *http.Request, response http.ResponseWriter, schemeName string) (auth.Handler, error) {
	scheme := p.schemes.GetScheme(schemeName)
	if scheme == nil {
		return nil, nil
	}
	return &unsupportedHandler{scheme: scheme}, nil
}

type NoopClaimsTransformation struct{}

func NewNoopClaimsTransformation() *NoopClaimsTransformation {
	return &NoopClaimsTransformation{}
}

func (NoopClaimsTransformation) Transform(principal *claims.ClaimsPrincipal) (*claims.ClaimsPrincipal, error) {
	return principal, nil
}

type Service struct {
	schemes  auth.SchemeProvider
	handlers auth.HandlerProvider
}

func NewService(schemes auth.SchemeProvider, handlers auth.HandlerProvider) *Service {
	return &Service{schemes: schemes, handlers: handlers}
}

func (s *Service) Authenticate(r *http.Request, w http.ResponseWriter, scheme string) (*auth.Result, error) {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return auth.NoResult(), err
	}
	return handler.Authenticate()
}

func (s *Service) Challenge(r *http.Request, w http.ResponseWriter, scheme string, properties *auth.Properties) error {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	return handler.Challenge(properties)
}

func (s *Service) Forbid(r *http.Request, w http.ResponseWriter, scheme string, properties *auth.Properties) error {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	return handler.Forbid(properties)
}

func (s *Service) SignIn(r *http.Request, w http.ResponseWriter, scheme string, principal *claims.ClaimsPrincipal, properties *auth.Properties) error {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	if signIn, ok := handler.(auth.SignInHandler); ok {
		return signIn.SignIn(principal, properties)
	}
	return fmt.Errorf("sign-in is unsupported")
}

func (s *Service) SignOut(r *http.Request, w http.ResponseWriter, scheme string, properties *auth.Properties) error {
	handler, err := s.handlers.GetHandler(r, w, scheme)
	if err != nil || handler == nil {
		return err
	}
	if signOut, ok := handler.(auth.SignOutHandler); ok {
		return signOut.SignOut(properties)
	}
	return fmt.Errorf("sign-out is unsupported")
}

func Middleware(provider auth.SchemeProvider, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
}

type unsupportedHandler struct {
	scheme *auth.Scheme
}

func (h *unsupportedHandler) Initialize(request *http.Request, response http.ResponseWriter, scheme *auth.Scheme) error {
	h.scheme = scheme
	return nil
}

func (h *unsupportedHandler) Authenticate() (*auth.Result, error) { return auth.NoResult(), nil }
func (h *unsupportedHandler) Challenge(*auth.Properties) error {
	return fmt.Errorf("challenge is unsupported")
}
func (h *unsupportedHandler) Forbid(*auth.Properties) error {
	return fmt.Errorf("forbid is unsupported")
}
