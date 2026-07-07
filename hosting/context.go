// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting

import (
	"context"
	"net/http"

	"github.com/gonewx/godi"
)

type scopeContextKey struct{}

func ContextWithScope(ctx context.Context, scope godi.Provider) context.Context {
	return context.WithValue(ctx, scopeContextKey{}, scope)
}

func ScopeFrom(ctx context.Context) godi.Provider {
	if scope, ok := ctx.Value(scopeContextKey{}).(godi.Provider); ok && scope != nil {
		return scope
	}
	return nil
}

// EndpointHandler handles one routed endpoint request.
// input: response/request -> behavior: process or reject endpoint -> output: error.
type EndpointHandler interface {
	Process(http.ResponseWriter, *http.Request) error
}
