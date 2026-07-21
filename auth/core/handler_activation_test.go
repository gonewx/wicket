// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package core

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/hosting"
	"github.com/stretchr/testify/require"
)

// spyHandler records its Initialize arguments and returns a preset result so
// tests can assert activation, initialization, and authentication behavior.
type spyHandler struct {
	initialized int
	gotRequest  *http.Request
	gotResponse http.ResponseWriter
	gotScheme   *auth.Scheme
	result      *auth.Result
}

func (h *spyHandler) Initialize(request *http.Request, response http.ResponseWriter, scheme *auth.Scheme) error {
	h.initialized++
	h.gotRequest = request
	h.gotResponse = response
	h.gotScheme = scheme
	return nil
}

func (h *spyHandler) Authenticate() (*auth.Result, error) {
	if h.result == nil {
		return auth.NoResult(), nil
	}
	return h.result, nil
}

func (h *spyHandler) Challenge(*auth.Properties) error { return nil }
func (h *spyHandler) Forbid(*auth.Properties) error    { return nil }

// keyedProvider is a godi.Provider test double that resolves auth.Handler by
// scheme name as a keyed service and optionally exposes an unkeyed service map.
type keyedProvider struct {
	factories map[string]func() auth.Handler
	services  map[reflect.Type]any
}

func newKeyedProvider() *keyedProvider {
	return &keyedProvider{
		factories: map[string]func() auth.Handler{},
		services:  map[reflect.Type]any{},
	}
}

func (p *keyedProvider) GetService(t reflect.Type) any {
	return p.services[t]
}

func (p *keyedProvider) IsService(t reflect.Type) bool {
	_, ok := p.services[t]
	return ok
}

func (p *keyedProvider) IsKeyedService(t reflect.Type, key any) bool {
	if key == nil {
		return p.IsService(t)
	}
	if t == reflect.TypeFor[auth.Handler]() {
		name, ok := key.(string)
		if !ok {
			return false
		}
		_, ok = p.factories[name]
		return ok
	}
	return false
}

func (p *keyedProvider) GetKeyedService(t reflect.Type, key any) any {
	if key == nil {
		return p.GetService(t)
	}
	if t == reflect.TypeFor[auth.Handler]() {
		name, ok := key.(string)
		if !ok {
			return nil
		}
		if factory, ok := p.factories[name]; ok {
			return factory()
		}
	}
	return nil
}

func (p *keyedProvider) GetKeyedServices(reflect.Type, any) []any { return nil }
func (p *keyedProvider) CreateScope() godi.Scope                  { return p }
func (p *keyedProvider) Close() error                             { return nil }

// TestHandlerProviderResolvesByKeyAndInitializes covers PR1: a registered scheme
// resolves its handler through the request scope keyed by scheme name, and the
// handler is initialized with the request, response, and scheme before return.
func TestHandlerProviderResolvesByKeyAndInitializes(t *testing.T) {
	t.Parallel()

	schemes := NewSchemeProvider(auth.NewOptions())
	if err := schemes.AddScheme(auth.NewScheme("k1", "handler")); err != nil {
		t.Fatalf("AddScheme: %v", err)
	}

	spy := &spyHandler{}
	provider := newKeyedProvider()
	provider.factories["k1"] = func() auth.Handler { return spy }

	handlers := NewHandlerProvider(schemes, provider)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	got, err := handlers.GetHandler(request, response, "k1")
	require.NoError(t, err)
	require.Same(t, spy, got, "handler must come from keyed scope resolution, not be self-built")
	require.Equal(t, 1, spy.initialized, "handler must be initialized before return")
	require.Same(t, request, spy.gotRequest)
	require.Same(t, response, spy.gotResponse)
	require.Equal(t, "k1", spy.gotScheme.Name)
}

// TestHandlerProviderMissingScheme covers KR5: an unregistered scheme returns
// (nil, nil); a registered scheme with no resolvable handler returns an error
// naming the scheme.
func TestHandlerProviderMissingScheme(t *testing.T) {
	t.Parallel()

	schemes := NewSchemeProvider(auth.NewOptions())
	if err := schemes.AddScheme(auth.NewScheme("registered", "handler")); err != nil {
		t.Fatalf("AddScheme: %v", err)
	}

	handlers := NewHandlerProvider(schemes, newKeyedProvider())
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	got, err := handlers.GetHandler(request, response, "unknown")
	require.NoError(t, err)
	require.Nil(t, got)

	got, err = handlers.GetHandler(request, response, "registered")
	require.Nil(t, got)
	require.Error(t, err)
	require.Contains(t, err.Error(), "registered")
}

// TestHandlerProviderCachesPerScheme covers KR4 within a scope: repeated
// GetHandler for the same scheme returns the same instance and initializes once.
func TestHandlerProviderCachesPerScheme(t *testing.T) {
	t.Parallel()

	schemes := NewSchemeProvider(auth.NewOptions())
	if err := schemes.AddScheme(auth.NewScheme("k1", "handler")); err != nil {
		t.Fatalf("AddScheme: %v", err)
	}

	provider := newKeyedProvider()
	provider.factories["k1"] = func() auth.Handler { return &spyHandler{} }

	handlers := NewHandlerProvider(schemes, provider)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	first, err := handlers.GetHandler(request, response, "k1")
	require.NoError(t, err)
	second, err := handlers.GetHandler(request, response, "k1")
	require.NoError(t, err)
	require.Same(t, first, second, "same request same scheme must reuse the cached handler")
	require.Equal(t, 1, first.(*spyHandler).initialized, "cache hit must not re-initialize")
}

// TestServiceAuthenticateReturnsResult covers SV1: authenticating a registered,
// activated scheme returns a non-nil result and no error.
func TestServiceAuthenticateReturnsResult(t *testing.T) {
	t.Parallel()

	schemes := NewSchemeProvider(auth.NewOptions())
	if err := schemes.AddScheme(auth.NewScheme("sv1", "handler")); err != nil {
		t.Fatalf("AddScheme: %v", err)
	}

	principal := claims.NewClaimsPrincipal()
	provider := newKeyedProvider()
	provider.factories["sv1"] = func() auth.Handler {
		return &spyHandler{result: &auth.Result{Principal: principal}}
	}

	service := NewService(schemes, NewHandlerProvider(schemes, provider))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	result, err := service.Authenticate(request, response, "sv1")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.False(t, result.None)
	require.Same(t, principal, result.Principal)
}

// TestMiddlewareAuthenticatesDefaultScheme verifies that the middleware
// authenticates the default authenticate scheme and places the result in the
// request context for downstream consumption.
func TestMiddlewareAuthenticatesDefaultScheme(t *testing.T) {
	t.Parallel()

	options := auth.NewOptions()
	options.DefaultScheme = "def"
	schemes := NewSchemeProvider(options)
	if err := schemes.AddScheme(auth.NewScheme("def", "handler")); err != nil {
		t.Fatalf("AddScheme: %v", err)
	}

	principal := claims.NewClaimsPrincipal()
	provider := newKeyedProvider()
	provider.factories["def"] = func() auth.Handler {
		return &spyHandler{result: &auth.Result{Principal: principal}}
	}
	handlers := NewHandlerProvider(schemes, provider)
	provider.services[reflect.TypeFor[auth.HandlerProvider]()] = auth.HandlerProvider(handlers)

	var seen *auth.Result
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ResultFromContext(r.Context())
	})

	middleware := Middleware(schemes, nil, "")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(hosting.ContextWithScope(request.Context(), provider))
	response := httptest.NewRecorder()

	middleware(downstream).ServeHTTP(response, request)

	require.NotNil(t, seen, "downstream must read the authentication result from context")
	require.False(t, seen.None)
	require.Same(t, principal, seen.Principal)
}

// TestMiddlewareNoDefaultSchemePassesThrough confirms an anonymous request with
// no default authenticate scheme is not blocked and carries no result.
func TestMiddlewareNoDefaultSchemePassesThrough(t *testing.T) {
	t.Parallel()

	schemes := NewSchemeProvider(auth.NewOptions())
	provider := newKeyedProvider()

	reached := false
	var seen *auth.Result
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		seen = ResultFromContext(r.Context())
	})

	middleware := Middleware(schemes, nil, "")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(hosting.ContextWithScope(request.Context(), provider))
	response := httptest.NewRecorder()

	middleware(downstream).ServeHTTP(response, request)

	require.True(t, reached, "middleware must not block anonymous requests")
	require.Nil(t, seen)
}
