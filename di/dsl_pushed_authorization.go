// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// godi-gen DSL input — DO NOT DELETE.
// godi-gen scans this file's godi.Add* calls at code-generation time to produce
// container_gen.go. These functions are never called at runtime; they exist solely
// as declarative registration markers for the generator.

package di

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

// registerPushedAuthorization wires pushed authorization requests (RFC 9126).
// The routes are singletons built with the root container, before the host
// can enable the feature, so their handler functions read the declaration on
// every request and yield no handler while the feature is not enabled; the
// mutual TLS alias additionally needs mutual TLS client authentication.
func registerPushedAuthorization() {
	var r godi.Registry

	godi.AddTransientFactory[*handlers.PushedAuthorizationRequestHandler](&r, newPushedAuthorizationRequestHandlerFromProvider)

	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(wicket.EndpointNamesPushedAuthorizationRequest, wicket.ProtocolRoutePathsPushedAuthorization, pushedAuthorizationEndpointHandler)
	})
	godi.AddSingletonFactory[*hosting.Endpoint](&r, func(p godi.Provider) *hosting.Endpoint {
		return newEndpoint(wicket.EndpointNamesPushedAuthorizationRequest, wicket.ProtocolRoutePathsMtlsPushedAuthorization, pushedAuthorizationMtlsEndpointHandler)
	})
}

// pushedAuthorizationEndpointHandler serves the pushed authorization request
// route while the feature is enabled and yields no handler otherwise, so the
// request falls through as if the route were not registered.
func pushedAuthorizationEndpointHandler(p godi.Provider) (hosting.EndpointHandler, error) {
	if !godi.GetRequired[*ServerConfig](p).PushedAuthorizationRequestsEnabled() {
		return nil, nil
	}
	return godi.GetRequired[*handlers.PushedAuthorizationRequestHandler](p), nil
}

// pushedAuthorizationMtlsEndpointHandler serves the mutual TLS alias route
// while both pushed authorization and mutual TLS client authentication are
// enabled, and yields no handler otherwise.
func pushedAuthorizationMtlsEndpointHandler(p godi.Provider) (hosting.EndpointHandler, error) {
	cfg := godi.GetRequired[*ServerConfig](p)
	if !cfg.PushedAuthorizationRequestsEnabled() || !cfg.ClientCertificateAuthenticationEnabled() {
		return nil, nil
	}
	return godi.GetRequired[*handlers.PushedAuthorizationRequestHandler](p), nil
}

func newPushedAuthorizationRequestHandlerFromProvider(p godi.Provider) *handlers.PushedAuthorizationRequestHandler {
	return handlers.NewPushedAuthorizationRequestHandler(
		clientAuthenticatorFromProvider(p),
		godi.GetRequired[validators.AuthorizeRequestValidator](p),
		pushedAuthorizationFromProvider(p),
		godi.GetRequired[*slog.Logger](p),
	)
}

// pushedAuthorization is what the enabled feature hands to the validator,
// the authorize handlers and the push endpoint.
type pushedAuthorization interface {
	validators_impl.PushedAuthorizationResolver
	handlers.PushedAuthorizationConsumer
	handlers.PushedAuthorizationPusher
}

// pushedAuthorizationFromProvider returns the pushed authorization service of
// the enabled feature. When it cannot be built, the seams being unusable,
// the result fails every operation, so pushed requests are answered with a
// server error rather than accepted unchecked. It must only be called while
// the feature is enabled.
func pushedAuthorizationFromProvider(p godi.Provider) pushedAuthorization {
	cfg := godi.GetRequired[*ServerConfig](p)
	service, err := cfg.pushedAuthorizationService(
		godi.GetRequired[storage.ClientStore](p),
		godi.GetRequired[services.SystemClock](p),
	)
	if err != nil {
		if logger, ok := godi.Get[*slog.Logger](p); ok && logger != nil {
			logger.Error("pushed authorization requests are enabled but cannot be served", slog.String("error", err.Error()))
		}
		return unavailablePushedAuthorization{err: err, required: cfg.PushedAuthorizationRequestsOptions().RequireForAllClients}
	}
	return service
}

// unavailablePushedAuthorization stands for a pushed authorization service
// that could not be built: every operation fails with err.
type unavailablePushedAuthorization struct {
	err      error
	required bool
}

func (u unavailablePushedAuthorization) Resolve(context.Context, string, string, string, bool) (url.Values, string, error) {
	return nil, "", u.err
}

func (u unavailablePushedAuthorization) Required(client *storage_models.Client) bool {
	return u.required || (client != nil && client.RequirePushedAuthorizationRequests)
}

func (u unavailablePushedAuthorization) Consume(context.Context, string, string) error {
	return u.err
}

func (u unavailablePushedAuthorization) Push(context.Context, *storage_models.Client, url.Values) (string, int, error) {
	return "", 0, u.err
}

var _ pushedAuthorization = (*pushedauth.Service)(nil)
