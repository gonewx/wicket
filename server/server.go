// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"

	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/hosting"
	dynamicschemes "github.com/gonewx/wicket/hosting/dynamic/schemes"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
)

func DefaultLogger() *slog.Logger {

	opts := slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
	}

	return slog.New(slog.NewJSONHandler(os.Stdout, &opts))
}

type Server struct {
	Logger   *slog.Logger
	provider godi.Provider
}

func WithLogger(logger *slog.Logger) gois.Option[Server] {
	return func(s *Server) {
		s.Logger = logger
	}
}

// From: IdentityServer4/src/IdentityServer/Configuration/IdentityServerApplicationBuilderExtensions.cs
func DefaultServer(p godi.Provider, opts ...gois.Option[Server]) (*Server, error) {
	if p == nil {
		return nil, fmt.Errorf("identity server provider is required")
	}

	s := &Server{provider: p}
	for _, opt := range opts {
		opt(s)
	}

	if s.Logger == nil {
		s.Logger = DefaultLogger()
	}

	return s, nil
}

func (s *Server) UseIdentityServer() func(http.Handler) http.Handler {
	s.Validate()

	opts := godi.GetRequired[*config_options.IdentityServerOptions](s.provider)
	dynamicProviders := opts.CleanRoomProviderGap

	schemeAuthMiddleware := dynamicschemes.UseSchemeAuthMiddleware(s.Logger, dynamicProviders)

	schemeProvider := godi.GetRequired[auth.SchemeProvider](s.provider)
	authCoreMiddleware := authcore.Middleware(schemeProvider, s.Logger)

	// AD-10: startup assembly resolves endpoint routing from the injected Provider,
	// matching dotnet app.ApplicationServices.
	router := godi.GetRequired[hosting.EndpointRouter](s.provider)

	idsrvMiddleware := hosting.NewMiddleware(
		s.Logger,
		router,
	)

	return func(next http.Handler) http.Handler {
		return schemeAuthMiddleware(
			authCoreMiddleware(
				idsrvMiddleware.Use(next),
			),
		)
	}
}

func (s *Server) Validate() {
	logger := s.Logger

	logger.Info("Starting gois IdentityServer version {version} ({netversion})")

	// From: Configuration/IdentityServerApplicationBuilderExtensions.cs#L57
	// AD-10: startup assembly resolves validation dependencies from the injected
	// Provider, matching dotnet app.ApplicationServices.
	opts := godi.GetRequired[*config_options.IdentityServerOptions](s.provider)

	persistedGrantStore := s.TestService(
		s.provider,
		resolveService[storage.PersistedGrantStore],
		logger,
		"No storage mechanism for grants specified. Use the 'AddInMemoryPersistedGrants' extension method to register a development version.",
		true,
	).(storage.PersistedGrantStore)

	s.TestService(
		s.provider,
		resolveService[storage.ClientStore],
		logger,
		"No storage mechanism for clients specified. Use the 'AddInMemoryClients' extension method to register a development version.",
		true,
	)

	if _, ok := persistedGrantStore.(*storage_memory.MemoryPersistedGrantStore); ok {
		logger.Info("You are using the in-memory version of the persisted grant store. This will store consent decisions, authorization codes, refresh and reference tokens in memory only. If you are using any of those features in production, you want to switch to a different store implementation.")
	}

	s.ValidateOptions(opts, logger)

	return
}

func (s *Server) ValidateSchemes(logger *slog.Logger) error {
	opts := godi.GetRequired[*config_options.IdentityServerOptions](s.provider)
	schemes := godi.GetRequired[auth.SchemeProvider](s.provider)

	if schemes.GetDefaultAuthenticateScheme() == nil && opts.Authentication.CookieAuthenticationScheme != "" {
		logger.Warn("No authentication scheme has been set. Setting either a default authentication scheme or a CookieAuthenticationScheme on IdentityServerOptions is required.")

		return nil
	}

	// TODO:
	// var authenticationScheme *auth.Scheme

	// if opts.Authentication.CookieAuthenticationScheme != "" {
	// 	authenticationScheme = schemes.GetScheme(opts.Authentication.CookieAuthenticationScheme)
	// 	logger.Infof("Using explicitly configured authentication scheme  for IdentityServer", slog.String("scheme", opts.Authentication.CookieAuthenticationScheme))
	// } else {
	// 	authenticationScheme = schemes.GetDefaultAuthenticateScheme()
	// 	logger.Infof("Using the default authentication scheme for IdentityServer", slog.String("scheme", opts.Authentication.CookieAuthenticationScheme))
	// }

	logger.Debug("Using as default scheme for authentication", slog.String("scheme", schemes.GetDefaultAuthenticateScheme().Name))
	logger.Debug("Using as default scheme for sign-in", slog.String("scheme", schemes.GetDefaultSignInScheme().Name))
	logger.Debug("Using as default scheme for sign-out", slog.String("scheme", schemes.GetDefaultSignOutScheme().Name))
	logger.Debug("Using as default scheme for challenge", slog.String("scheme", schemes.GetDefaultChallengeScheme().Name))
	logger.Debug("Using as default scheme for forbid", slog.String("scheme", schemes.GetDefaultForbidScheme().Name))

	return nil
}

func (s *Server) ValidateOptions(opts *config_options.IdentityServerOptions, logger *slog.Logger) {
	if strings.TrimSpace(opts.IssuerUri) != "" {
		logger.Debug("Custom IssuerUri set to", slog.String("uri", opts.IssuerUri))
	}

	if strings.TrimSpace(opts.UserInteraction.LogoutIdParameter) == "" {
		panic("LogoutIdParameter is not configured")
	}

	if strings.TrimSpace(opts.UserInteraction.ErrorUrl) == "" {
		panic("ErrorUrl is not configured")
	}

	if strings.TrimSpace(opts.UserInteraction.ErrorIdParameter) == "" {
		panic("ErrorIdParameter is not configured")
	}

	if strings.TrimSpace(opts.UserInteraction.ConsentUrl) == "" {
		panic("ConsentUrl is not configured")
	}

	if strings.TrimSpace(opts.UserInteraction.ConsentReturnUrlParameter) == "" {
		panic("ConsentReturnUrlParameter is not configured")
	}

	if strings.TrimSpace(opts.UserInteraction.CustomRedirectReturnUrlParameter) == "" {
		panic("CustomRedirectReturnUrlParameter is not configured")
	}

	if strings.TrimSpace(opts.Authentication.CheckSessionCookieName) == "" {
		panic("CheckSessionCookieName is not configured")
	}

	if strings.TrimSpace(opts.Cors.CorsPolicyName) == "" {
		panic("CorsPolicyName is not configured")
	}
}

type serviceResolver func(godi.Provider) any

func resolveService[T any](p godi.Provider) any {
	service, ok := godi.Get[T](p)
	if !ok {
		return nil
	}
	return service
}

func (s *Server) TestService(p godi.Provider, resolve serviceResolver, logger *slog.Logger, message string, doThrow bool) any {
	service := resolve(p)
	if service != nil {
		return service
	}

	if message == "" {
		message = "Required service is not registered. Aborting startup"
	}
	logger.Error(message)

	if doThrow {
		panic(message)
	}

	return nil
}
