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
type WicketAuthenticationService struct {
	inner auth.Service
}

func NewWicketAuthenticationService(
	decorator *gois.Decorator[auth.Service],
	schemes auth.SchemeProvider,
	clock services.SystemClock,
	user services.UserSession,
	logger *slog.Logger,
	options *config_options.WicketOptions,
) *WicketAuthenticationService {
	if decorator == nil {
		return &WicketAuthenticationService{}
	}
	return &WicketAuthenticationService{inner: decorator.Instance}
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
	return s.inner.SignOut(request, response, scheme, properties)
}
