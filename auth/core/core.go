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
	options *auth.Options
}

func NewSchemeProvider(options *auth.Options) *SchemeProvider {
	if options == nil {
		options = auth.NewOptions()
	}
	return &SchemeProvider{options: options}
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

// Default-scheme resolution comes strictly from configuration, never from an
// implicitly-chosen registered scheme. Each category consults its own configured
// default and falls back through a chain that ends at the overall DefaultScheme.
// Sign-out falls back to the sign-in default; forbid falls back to the challenge
// default. Fallback does not check whether the resolved scheme declares the
// matching handler capability.

func (p *SchemeProvider) GetDefaultAuthenticateScheme() *auth.Scheme {
	return p.schemeByName(p.defaultAuthenticateName())
}

func (p *SchemeProvider) GetDefaultChallengeScheme() *auth.Scheme {
	return p.schemeByName(p.defaultChallengeName())
}

func (p *SchemeProvider) GetDefaultForbidScheme() *auth.Scheme {
	return p.schemeByName(firstNonEmpty(p.options.DefaultForbidScheme, p.defaultChallengeName()))
}

func (p *SchemeProvider) GetDefaultSignInScheme() *auth.Scheme {
	return p.schemeByName(p.defaultSignInName())
}

func (p *SchemeProvider) GetDefaultSignOutScheme() *auth.Scheme {
	return p.schemeByName(firstNonEmpty(p.options.DefaultSignOutScheme, p.defaultSignInName()))
}

func (p *SchemeProvider) defaultAuthenticateName() string {
	return firstNonEmpty(p.options.DefaultAuthenticateScheme, p.options.DefaultScheme)
}

func (p *SchemeProvider) defaultChallengeName() string {
	return firstNonEmpty(p.options.DefaultChallengeScheme, p.options.DefaultScheme)
}

func (p *SchemeProvider) defaultSignInName() string {
	return firstNonEmpty(p.options.DefaultSignInScheme, p.options.DefaultScheme)
}

// schemeByName resolves a configured default name to a registered scheme; an
// empty name (no default configured) yields no scheme.
func (p *SchemeProvider) schemeByName(name string) *auth.Scheme {
	if name == "" {
		return nil
	}
	return p.GetScheme(name)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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

// RemoveScheme drops the named scheme and reports whether it was present. A
// removed name is released for re-registration.
func (p *SchemeProvider) RemoveScheme(name string) bool {
	for i, scheme := range p.schemes {
		if scheme.Name == name {
			p.schemes = append(p.schemes[:i], p.schemes[i+1:]...)
			return true
		}
	}
	return false
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
