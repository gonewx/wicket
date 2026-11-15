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
	"github.com/gonewx/wicket/services"
	services_impl "github.com/gonewx/wicket/services/impl"
	"github.com/gonewx/wicket/storage"
)

// registerRefreshTokenConsumption replaces the refresh token service
// registration with a factory that applies the declared refresh token
// consumption. Being registered later, it takes precedence.
func registerRefreshTokenConsumption() {
	var r godi.Registry

	godi.AddTransientFactory[services.RefreshTokenService](&r, refreshTokenServiceFromProvider)
}

// refreshTokenServiceFromProvider builds the refresh token service exactly as
// the core registration does and applies the declared consumption. The
// declaration is read here, per resolution, because the host declares it
// after the container is built. The clock is injected whatever the
// consumption, so that a token marked as consumed under an earlier
// configuration still revokes its successors when replayed.
func refreshTokenServiceFromProvider(p godi.Provider) services.RefreshTokenService {
	service := services_impl.NewRefreshTokenService(
		godi.GetRequired[storage.RefreshTokenStore](p),
		godi.GetRequired[services.HandleGenerationService](p),
	)
	service.SetConsumption(
		godi.GetRequired[*ServerConfig](p).RefreshTokenConsumption(),
		godi.GetRequired[services.SystemClock](p),
		godi.GetRequired[*slog.Logger](p),
	)
	// A refresh token records its browser session only while the grants of
	// a session are revoked with it, see session_grant_revocation.go.
	service.SetSessionBinding(godi.GetRequired[*ServerConfig](p).RevokeGrantsOnSessionSubjectChange())
	return service
}
