// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/accessor"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dpop"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
	models_contexts "github.com/gonewx/wicket/models/contexts"
	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/responses"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/utils"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

func newServerConfigLogger(config *ServerConfig, fallback *slog.Logger) *slog.Logger {
	if config != nil && config.Logger() != nil {
		return config.Logger()
	}
	return fallback
}

func newEndpoint(name string, path string, handler func(godi.Provider) (hosting.EndpointHandler, error)) *hosting.Endpoint {
	// Route paths are declared without a leading slash, while incoming request
	// paths always carry one; normalize here so the endpoint router can match the
	// registered path against the request path.
	return &hosting.Endpoint{Name: name, Path: utils.EnsureLeadingSlash(path), Handler: handler}
}

func endpointHandler[T hosting.EndpointHandler](p godi.Provider) (hosting.EndpointHandler, error) {
	return godi.GetRequired[T](p), nil
}

func requestFromProvider(p godi.Provider) *http.Request {
	if contextAccessor, ok := godi.Get[accessor.HttpContextAccessor](p); ok {
		return contextAccessor.Request()
	}
	return nil
}

func responseFromProvider(p godi.Provider) http.ResponseWriter {
	if contextAccessor, ok := godi.Get[accessor.HttpContextAccessor](p); ok {
		if responseAccessor, ok := contextAccessor.(accessor.HttpResponseWriterAccessor); ok {
			return responseAccessor.ResponseWriter()
		}
	}
	return nil
}

func newAuthorizeHandlerFromProvider(p godi.Provider) *handlers.AuthorizeHandler {
	handler := handlers.NewAuthorizeHandlerWithOptions(
		godi.GetRequired[validators.AuthorizeRequestValidator](p),
		godi.GetRequired[responses.AuthorizeInteractionResponseGenerator](p),
		godi.GetRequired[responses.AuthorizeResponseGenerator](p),
		godi.GetRequired[services.UserSession](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
	if cfg, ok := godi.Get[*ServerConfig](p); ok && cfg.PushedAuthorizationRequestsEnabled() {
		handler.SetPushedAuthorizationConsumer(pushedAuthorizationFromProvider(p))
	}
	return handler
}

func newAuthorizeCallbackHandlerFromProvider(p godi.Provider) *handlers.AuthorizeCallbackHandler {
	parameters, _ := godi.Get[storage.AuthorizationParametersMessageStore](p)
	handler := handlers.NewAuthorizeCallbackHandlerWithOptions(
		godi.GetRequired[validators.AuthorizeRequestValidator](p),
		godi.GetRequired[responses.AuthorizeInteractionResponseGenerator](p),
		godi.GetRequired[responses.AuthorizeResponseGenerator](p),
		godi.GetRequired[services.UserSession](p),
		godi.GetRequired[storage.ConsentMessageStore](p),
		parameters,
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
	if cfg, ok := godi.Get[*ServerConfig](p); ok && cfg.PushedAuthorizationRequestsEnabled() {
		handler.SetPushedAuthorizationConsumer(pushedAuthorizationFromProvider(p))
	}
	return handler
}

func newTokenHandlerFromProvider(p godi.Provider) *handlers.TokenHandler {
	handler := handlers.NewTokenHandlerWithOptions(
		withClientCredentialsAuthentication(p, withCertificateBoundAccessTokens(p, clientAuthenticatorFromProvider(p))),
		godi.GetRequired[validators.TokenRequestValidator](p),
		godi.GetRequired[responses.TokenResponseGenerator](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
	// The replay registry is resolved only while DPoP is enabled.
	if cfg, ok := godi.Get[*ServerConfig](p); ok && cfg.DPoPEnabled() {
		options := cfg.DPoPOptions()
		handler.SetDPoP(
			dpop.NewVerifier(options),
			godi.GetRequired[replay.Registry](p),
			options,
			godi.GetRequired[services.SystemClock](p),
		)
		// The nonce key seam is resolved only while nonces are required.
		if options.RequireNonce {
			keys, err := cfg.dpopNonceKeysForFeature()
			if err != nil {
				if logger, ok := godi.Get[*slog.Logger](p); ok && logger != nil {
					logger.Error("DPoP server nonces are required but cannot be served", slog.String("error", err.Error()))
				}
				keys = failingNonceKeys{err: err}
			}
			handler.SetDPoPNonces(dpop.NewNonceSealer(keys, options))
		}
	}
	return handler
}

func newDiscoveryHandlerFromProvider(p godi.Provider) *handlers.DiscoveryHandler {
	endpoints := godi.GetServices[*hosting.Endpoint](p)
	endpointPaths := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpointPaths = append(endpointPaths, endpoint.Path)
	}
	handler := handlers.NewDiscoveryHandler(
		godi.GetRequired[responses.DiscoveryResponseGenerator](p),
		godi.GetRequired[services.ServerUrls](p),
		godi.GetRequired[services.IssuerNameService](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		endpointPaths,
		godi.GetRequired[services.BackchannelLogoutService](p),
		godi.GetRequired[validators.SecretsListParser](p),
		godi.GetRequired[*slog.Logger](p),
	)
	if algorithms, ok := clientAssertionSigningAlgorithms(p); ok {
		handler.SetClientAssertionSigningAlgorithms(algorithms)
	}
	if cfg, ok := godi.Get[*ServerConfig](p); ok && cfg.ClientCertificateAuthenticationEnabled() {
		handler.ServeClientCertificateAuthentication()
	}
	if cfg, ok := godi.Get[*ServerConfig](p); ok && cfg.AsymmetricRequestObjectsRequired() {
		handler.ServeAsymmetricRequestObjectsOnly()
	}
	if cfg, ok := godi.Get[*ServerConfig](p); ok && cfg.PushedAuthorizationRequestsEnabled() {
		handler.ServePushedAuthorization(cfg.PushedAuthorizationRequestsOptions().RequireForAllClients)
	}
	if cfg, ok := godi.Get[*ServerConfig](p); ok && cfg.DPoPEnabled() {
		handler.ServeDPoP(cfg.DPoPOptions().SigningAlgorithms)
	}
	handler.ServeSignedIntrospection(godi.GetRequired[services.KeyMaterialService](p))
	return handler
}

func newDiscoveryKeyHandlerFromProvider(p godi.Provider) *handlers.DiscoveryKeyHandler {
	return handlers.NewDiscoveryKeyHandler(
		godi.GetRequired[responses.DiscoveryResponseGenerator](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newCheckSessionHandlerFromProvider(p godi.Provider) *handlers.CheckSessionHandler {
	return handlers.NewCheckSessionHandler(
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newBackchannelAuthenticationHandlerFromProvider(p godi.Provider) *handlers.BackchannelAuthenticationHandler {
	return handlers.NewBackchannelAuthenticationHandlerWithOptions(
		clientAuthenticatorFromProvider(p),
		godi.GetRequired[validators.BackchannelAuthenticationRequestValidator](p),
		godi.GetRequired[*config_options.WicketOptions](p),
	)
}

func newIntrospectionHandlerFromProvider(p godi.Provider) *handlers.IntrospectionHandler {
	handler := handlers.NewIntrospectionHandlerWithOptions(
		apiAuthenticatorFromProvider(p),
		godi.GetRequired[validators.IntrospectionRequestValidator](p),
		godi.GetRequired[responses.IntrospectionResponseGenerator](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
	handler.ServeSignedResponses(
		godi.GetRequired[services.KeyMaterialService](p),
		godi.GetRequired[services.IssuerNameService](p),
		godi.GetRequired[services.SystemClock](p),
	)
	return handler
}

func newTokenRevocationHandlerFromProvider(p godi.Provider) *handlers.TokenRevocationHandler {
	return handlers.NewTokenRevocationHandler(
		clientAuthenticatorFromProvider(p),
		godi.GetRequired[validators.TokenRevocationRequestValidator](p),
		godi.GetRequired[responses.TokenRevocationResponseGenerator](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newDeviceAuthorizationHandlerFromProvider(p godi.Provider) *handlers.DeviceAuthorizationHandler {
	return handlers.NewDeviceAuthorizationHandler(
		clientAuthenticatorFromProvider(p),
		godi.GetRequired[validators.DeviceAuthorizationRequestValidator](p),
		godi.GetRequired[responses.DeviceAuthorizationResponseGenerator](p),
		godi.GetRequired[services.ServerUrls](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newUserInfoHandlerFromProvider(p godi.Provider) *handlers.UserInfoHandler {
	handler := handlers.NewUserInfoHandler(
		godi.GetRequired[*validators_impl.BearerTokenUsageValidator](p),
		godi.GetRequired[validators.UserInfoRequestValidator](p),
		godi.GetRequired[responses.UserInfoResponseGenerator](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
	// A token bound to a client certificate is checked whether or not the
	// feature is enabled, so the handler always reads certificates from the
	// same source as the token endpoint.
	if cfg, ok := godi.Get[*ServerConfig](p); ok {
		handler.SetClientCertificateSource(cfg.ClientCertificateSource())
		// The replay registry is resolved only while DPoP is enabled.
		if cfg.DPoPEnabled() {
			options := cfg.DPoPOptions()
			handler.SetDPoP(
				dpop.NewVerifier(options),
				godi.GetRequired[replay.Registry](p),
				options,
				godi.GetRequired[services.SystemClock](p),
			)
		}
	}
	return handler
}

func newEndSessionHandlerFromProvider(p godi.Provider) *handlers.EndSessionHandler {
	return handlers.NewEndSessionHandler(
		godi.GetRequired[validators.EndSessionRequestValidator](p),
		godi.GetRequired[services.UserSession](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newEndSessionCallbackHandlerFromProvider(p godi.Provider) *handlers.EndSessionCallbackHandler {
	return handlers.NewEndSessionCallbackHandler(
		godi.GetRequired[validators.EndSessionRequestValidator](p),
		godi.GetRequired[services.BackchannelLogoutService](p),
		godi.GetRequired[storage.MessageStore[models_contexts.LogoutNotificationContext]](p),
		godi.GetRequired[services.SystemClock](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
}
