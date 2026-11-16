// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"log/slog"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/auth"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
)

// registerSessionGrantRevocation replaces the user session registration with
// a factory that revokes the grants of a browser session once another
// subject signs in on it, when the host declared it. Being registered later,
// it takes precedence.
func registerSessionGrantRevocation() {
	var r godi.Registry

	godi.AddScopedFactory[services.UserSession](&r, revokingUserSessionFromProvider)
}

// revokingUserSessionFromProvider builds the user session exactly as the core
// registration does. The revocation declaration is read here, per
// resolution, because the host declares it after the container is built;
// the stores and the session cookie protector are resolved only when it is
// declared. A declared revocation without a usable session cookie protector
// panics, whether or not Freeze was called.
func revokingUserSessionFromProvider(p godi.Provider) services.UserSession {
	session := services_impl.NewUserSession(
		godi.GetRequired[accessor.HttpContextAccessor](p),
		godi.GetRequired[auth.HandlerProvider](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[services.SystemClock](p),
		services_impl.NewServerUrlsFromAccessor(godi.GetRequired[accessor.HttpContextAccessor](p)),
		godi.GetRequired[*slog.Logger](p),
		godi.GetRequired[auth.SchemeProvider](p),
		godi.GetRequired[sessionpkg.Store](p),
	)
	if cfg := godi.GetRequired[*ServerConfig](p); cfg.RevokeGrantsOnSessionSubjectChange() {
		protector, err := cfg.sessionCookieProtectorForFeature()
		if err != nil {
			panic(err.Error())
		}
		session.SetSessionGrantRevoker(services_impl.NewSessionGrantRevoker(
			godi.GetRequired[storage.AuthorizationCodeStore](p),
			godi.GetRequired[storage.RefreshTokenStore](p),
			godi.GetRequired[storage.ReferenceTokenStore](p),
			godi.GetRequired[storage.PersistedGrantStore](p),
			godi.GetRequired[*slog.Logger](p),
		), protector)
	}
	return session
}
