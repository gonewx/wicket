// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting

import (
	"log/slog"
	"net/http"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/accessor"
)

type Middleware struct {
	logger *slog.Logger
	router EndpointRouter
}

func NewMiddleware(logger *slog.Logger, router EndpointRouter) *Middleware {
	return &Middleware{logger: logger, router: router}
}

func (m *Middleware) Use(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parent := ScopeFrom(r.Context())
		if parent == nil {
			next.ServeHTTP(w, r)
			return
		}
		scope := parent.CreateScope()
		defer scope.Close()

		if httpAccessor, ok := godi.Get[accessor.HttpContextAccessor](scope); ok {
			httpAccessor.SetRequest(r)
			if responseAccessor, ok := httpAccessor.(accessor.HttpResponseWriterAccessor); ok {
				responseAccessor.SetResponseWriter(w)
			}
		}

		r = r.WithContext(ContextWithScope(r.Context(), scope))
		handler, err := m.router.Find(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if handler == nil {
			handler, err = findAuthorizationServerMetadataHandler(m.router, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if handler == nil {
			next.ServeHTTP(w, r)
			return
		}
		if err := handler.Process(w, r); err != nil {
			http.Error(w, err.Error(), http.StatusNotImplemented)
		}
	})
}
