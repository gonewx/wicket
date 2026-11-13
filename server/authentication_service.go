// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package server

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
)

// WicketAuthenticationService delegates authentication operations through the decorated service.
// input: request/response/scheme/properties -> behavior: forward to inner service -> output: auth result or error.
// Signing out of the default sign-out scheme also ends the user's server-side
// session cookie, so a later request cannot pick the ended session up again.
type WicketAuthenticationService struct {
	inner   auth.Service
	schemes auth.SchemeProvider
	user    services.UserSession
	logger  *slog.Logger
}

func NewWicketAuthenticationService(
	decorator *wicket.Decorator[auth.Service],
	schemes auth.SchemeProvider,
	clock services.SystemClock,
	user services.UserSession,
	logger *slog.Logger,
	options *config_options.WicketOptions,
) *WicketAuthenticationService {
	service := &WicketAuthenticationService{schemes: schemes, user: user, logger: logger}
	if decorator != nil {
		service.inner = decorator.Instance
	}
	return service
}

func (s *WicketAuthenticationService) Authenticate(request *http.Request, response http.ResponseWriter, scheme string) (*auth.Result, error) {
	if s.inner == nil {
		return auth.NoResult(), nil
	}
	return s.inner.Authenticate(request, response, scheme)
}

func (s *WicketAuthenticationService) Challenge(request *http.Request, response http.ResponseWriter, scheme string, properties *auth.Properties) error {
	if s.inner == nil {
		return nil
	}
	return s.inner.Challenge(request, response, scheme, properties)
}

func (s *WicketAuthenticationService) Forbid(request *http.Request, response http.ResponseWriter, scheme string, properties *auth.Properties) error {
	if s.inner == nil {
		return nil
	}
	return s.inner.Forbid(request, response, scheme, properties)
}

func (s *WicketAuthenticationService) SignIn(request *http.Request, response http.ResponseWriter, scheme string, principal *claims.ClaimsPrincipal, properties *auth.Properties) error {
	if s.inner == nil {
		return nil
	}
	return s.inner.SignIn(request, response, scheme, principal, properties)
}

func (s *WicketAuthenticationService) SignOut(request *http.Request, response http.ResponseWriter, scheme string, properties *auth.Properties) error {
	if s.inner == nil {
		return nil
	}
	if s.user != nil && s.isDefaultSignOutScheme(scheme) {
		if err := s.user.RemoveSessionIdCookie(); err != nil && s.logger != nil {
			s.logger.Warn("sign-out: cannot remove the session cookie", slog.String("error", err.Error()))
		}
	}
	return s.inner.SignOut(request, response, scheme, properties)
}

// isDefaultSignOutScheme reports whether scheme names the default sign-out
// scheme; signing out of any other scheme (such as a temporary external
// sign-in scheme) leaves the user's session alone.
func (s *WicketAuthenticationService) isDefaultSignOutScheme(scheme string) bool {
	if scheme == "" {
		return true
	}
	if s.schemes == nil {
		return false
	}
	def := s.schemes.GetDefaultSignOutScheme()
	return def != nil && def.Name == scheme
}
