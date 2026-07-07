// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/accessor"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/hosting"
)

func newServerConfigLogger(config *ServerConfig, fallback *slog.Logger) *slog.Logger {
	if config != nil && config.Logger() != nil {
		return config.Logger()
	}
	return fallback
}

func newEndpoint(name string, path string, handler func(godi.Provider) (hosting.EndpointHandler, error)) *hosting.Endpoint {
	return &hosting.Endpoint{Name: name, Path: path, Handler: handler}
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

func newAuthorizeHandlerFromProvider(godi.Provider) *handlers.AuthorizeHandler {
	return handlers.NewAuthorizeHandler()
}

func newAuthorizeCallbackHandlerFromProvider(godi.Provider) *handlers.AuthorizeCallbackHandler {
	return handlers.NewAuthorizeCallbackHandler()
}

func newTokenHandlerFromProvider(godi.Provider) *handlers.TokenHandler {
	return handlers.NewTokenHandler()
}

func newDiscoveryHandlerFromProvider(godi.Provider) *handlers.DiscoveryHandler {
	return handlers.NewDiscoveryHandler()
}

func newDiscoveryKeyHandlerFromProvider(godi.Provider) *handlers.DiscoveryKeyHandler {
	return handlers.NewDiscoveryKeyHandler()
}

func newCheckSessionHandlerFromProvider(godi.Provider) *handlers.CheckSessionHandler {
	return handlers.NewCheckSessionHandler()
}

func newIntrospectionHandlerFromProvider(godi.Provider) *handlers.IntrospectionHandler {
	return handlers.NewIntrospectionHandler()
}

func newUserInfoHandlerFromProvider(godi.Provider) *handlers.UserInfoHandler {
	return handlers.NewUserInfoHandler()
}

func newEndSessionHandlerFromProvider(godi.Provider) *handlers.EndSessionHandler {
	return handlers.NewEndSessionHandler()
}

func newEndSessionCallbackHandlerFromProvider(godi.Provider) *handlers.EndSessionCallbackHandler {
	return handlers.NewEndSessionCallbackHandler()
}
