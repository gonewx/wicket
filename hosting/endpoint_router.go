// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0.
// Modifications Copyright 2026 Decker.

package hosting

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/gonewx/wicket"

	config_options "github.com/gonewx/wicket/config/options"
)

type EndpointRouter interface {
	Find(request *http.Request) (EndpointHandler, error)
}

type endpointRouter struct {
	endpoints []*Endpoint
	options   *config_options.WicketOptions
	logger    *slog.Logger
}

func NewEndpointRouter(
	endpoints []*Endpoint,
	options *config_options.WicketOptions,
	logger *slog.Logger,
) EndpointRouter {
	return &endpointRouter{
		endpoints: endpoints,
		options:   options,
		logger:    logger,
	}
}

func (r *endpointRouter) Find(request *http.Request) (EndpointHandler, error) {
	if request == nil {
		return nil, gois.ArgumentNullException
	}

	scope := ScopeFrom(request.Context())
	for _, endpoint := range r.endpoints {
		path := endpoint.Path
		if strings.ToLower(request.URL.Path) == strings.ToLower(path) {
			r.logger.Debug("Request path matched to endpoint type", slog.String("path", request.URL.Path), slog.String("endpoint", endpoint.Name))

			return endpoint.Handler(scope)
		}
	}

	r.logger.Debug("No endpoint entry found for request path", slog.String("path", request.URL.Path))

	return nil, nil
}
