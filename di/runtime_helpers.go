// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/accessor"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
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
	return handlers.NewAuthorizeHandler(
		godi.GetRequired[validators.AuthorizeRequestValidator](p),
		godi.GetRequired[responses.AuthorizeInteractionResponseGenerator](p),
		godi.GetRequired[responses.AuthorizeResponseGenerator](p),
		godi.GetRequired[services.UserSession](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newAuthorizeCallbackHandlerFromProvider(p godi.Provider) *handlers.AuthorizeCallbackHandler {
	parameters, _ := godi.Get[storage.AuthorizationParametersMessageStore](p)
	return handlers.NewAuthorizeCallbackHandler(
		godi.GetRequired[validators.AuthorizeRequestValidator](p),
		godi.GetRequired[responses.AuthorizeInteractionResponseGenerator](p),
		godi.GetRequired[responses.AuthorizeResponseGenerator](p),
		godi.GetRequired[services.UserSession](p),
		godi.GetRequired[storage.ConsentMessageStore](p),
		parameters,
		godi.GetRequired[*slog.Logger](p),
	)
}

func newTokenHandlerFromProvider(p godi.Provider) *handlers.TokenHandler {
	return handlers.NewTokenHandler(
		godi.GetRequired[validators.ClientSecretValidator](p),
		godi.GetRequired[validators.TokenRequestValidator](p),
		godi.GetRequired[responses.TokenResponseGenerator](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newDiscoveryHandlerFromProvider(p godi.Provider) *handlers.DiscoveryHandler {
	return handlers.NewDiscoveryHandler(
		godi.GetRequired[responses.DiscoveryResponseGenerator](p),
		godi.GetRequired[services.ServerUrls](p),
		godi.GetRequired[services.IssuerNameService](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
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
	return handlers.NewBackchannelAuthenticationHandler(
		godi.GetRequired[validators.ClientSecretValidator](p),
		godi.GetRequired[validators.BackchannelAuthenticationRequestValidator](p),
	)
}

func newIntrospectionHandlerFromProvider(p godi.Provider) *handlers.IntrospectionHandler {
	return handlers.NewIntrospectionHandler(
		godi.GetRequired[validators.ApiSecretValidator](p),
		godi.GetRequired[validators.IntrospectionRequestValidator](p),
		godi.GetRequired[responses.IntrospectionResponseGenerator](p),
		godi.GetRequired[*slog.Logger](p),
	)
}

func newUserInfoHandlerFromProvider(p godi.Provider) *handlers.UserInfoHandler {
	return handlers.NewUserInfoHandler(
		godi.GetRequired[*validators_impl.BearerTokenUsageValidator](p),
		godi.GetRequired[validators.UserInfoRequestValidator](p),
		godi.GetRequired[responses.UserInfoResponseGenerator](p),
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
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
		godi.GetRequired[*config_options.WicketOptions](p),
		godi.GetRequired[*slog.Logger](p),
	)
}
