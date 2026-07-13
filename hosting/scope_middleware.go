// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting

import (
	"net/http"

	"github.com/gonewx/godi"
)

// ScopeMiddleware attaches the root provider to requests.
// input: root provider/request -> behavior: store provider in request context -> output: wrapped handler.
func ScopeMiddleware(root godi.Provider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scope := root.CreateScope()
			defer scope.Close()
			next.ServeHTTP(w, r.WithContext(ContextWithScope(r.Context(), scope)))
		})
	}
}
