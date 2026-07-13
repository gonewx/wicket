// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"context"
	"fmt"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/hosting"
)

type featureContextKey struct{}

func ContextWithFeature(ctx context.Context, feature auth.Feature) context.Context {
	return context.WithValue(ctx, featureContextKey{}, feature)
}

func FeatureFrom(ctx context.Context) auth.Feature {
	if f, ok := ctx.Value(featureContextKey{}).(auth.Feature); ok {
		return f
	}
	return nil
}

func service(ctx context.Context) (auth.Service, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is nil")
	}
	scope := hosting.ScopeFrom(ctx)
	if scope == nil {
		return nil, fmt.Errorf("no request scope in context")
	}
	svc, ok := godi.Get[auth.Service](scope)
	if !ok || svc == nil {
		return nil, fmt.Errorf("auth service not available in request scope")
	}
	return svc, nil
}
