//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonewx/godi"
	gois "github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	authcore "github.com/gonewx/wicket/auth/core"
	"github.com/gonewx/wicket/hosting"
	"github.com/stretchr/testify/require"
)

// TestDefaultSchemeResolutionFromConfiguredOptions verifies that the container
// wires the configured overall default scheme name into the scheme provider,
// so every category default resolves to the registered scheme of that name
// through its fallback chain.
func TestDefaultSchemeResolutionFromConfiguredOptions(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	provider := godi.GetRequired[auth.SchemeProvider](root)
	require.NoError(t, provider.AddScheme(auth.NewScheme(gois.DefaultCookieAuthenticationScheme, "cookie")))

	resolvers := map[string]func() *auth.Scheme{
		"authenticate": provider.GetDefaultAuthenticateScheme,
		"challenge":    provider.GetDefaultChallengeScheme,
		"forbid":       provider.GetDefaultForbidScheme,
		"sign-in":      provider.GetDefaultSignInScheme,
		"sign-out":     provider.GetDefaultSignOutScheme,
	}
	for category, resolve := range resolvers {
		scheme := resolve()
		require.NotNil(t, scheme, "%s default must resolve", category)
		require.Equal(t, gois.DefaultCookieAuthenticationScheme, scheme.Name, "%s default must come from configuration", category)
	}
}

// TestDefaultSchemeUnregisteredNameResolvesToNil verifies that a configured
// default name with no matching registration yields no scheme instead of an
// implicitly-chosen registered scheme.
func TestDefaultSchemeUnregisteredNameResolvesToNil(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	provider := godi.GetRequired[auth.SchemeProvider](root)
	require.NoError(t, provider.AddScheme(auth.NewScheme("other", "custom")))

	require.Nil(t, provider.GetDefaultAuthenticateScheme(), "an unregistered configured default must resolve to nil, never to another registered scheme")
}

// TestRemoveSchemeThroughOuterProvider verifies that removal reaches the static
// registry through the merging provider and releases the name for
// re-registration.
func TestRemoveSchemeThroughOuterProvider(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	provider := godi.GetRequired[auth.SchemeProvider](root)
	require.NoError(t, provider.AddScheme(auth.NewScheme("removable", "custom")))
	require.NotNil(t, provider.GetScheme("removable"))

	require.True(t, provider.RemoveScheme("removable"))
	require.Nil(t, provider.GetScheme("removable"))
	require.False(t, provider.RemoveScheme("removable"), "removing an absent scheme must report false")

	require.NoError(t, provider.AddScheme(auth.NewScheme("removable", "custom")), "a removed name must be free for re-registration")
}

// TestRequestHandlerSchemesFilterThroughRoot verifies that only schemes marked
// as request handlers are enumerated by the provider resolved from the
// container.
func TestRequestHandlerSchemesFilterThroughRoot(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	provider := godi.GetRequired[auth.SchemeProvider](root)

	plain := auth.NewScheme("plain", "custom")
	require.NoError(t, provider.AddScheme(plain))
	remote := auth.NewScheme("remote", "custom")
	remote.HandlesRequests = true
	require.NoError(t, provider.AddScheme(remote))

	schemes, err := provider.GetRequestHandlerSchemes()
	require.NoError(t, err)
	require.Len(t, schemes, 1)
	require.Equal(t, "remote", schemes[0].Name)
}

// TestAuthenticationServiceOrchestratesRegisteredScheme verifies the service
// resolved from a request scope: authenticating the built-in cookie scheme
// yields the no-result outcome of its placeholder handler, and challenge is
// rejected by that handler.
func TestAuthenticationServiceOrchestratesRegisteredScheme(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	require.NoError(t, godi.GetRequired[auth.SchemeProvider](root).AddScheme(auth.NewScheme(gois.DefaultCookieAuthenticationScheme, "cookie")))

	scope := root.CreateScope()
	defer scope.Close()
	service := godi.GetRequired[*authcore.Service](scope)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	result, err := service.Authenticate(request, response, gois.DefaultCookieAuthenticationScheme)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.True(t, result.None, "the placeholder handler must authenticate to no result")

	err = service.Challenge(request, response, gois.DefaultCookieAuthenticationScheme, auth.NewProperties())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

// TestMiddlewareAnonymousRequestPassesThrough verifies the middleware over the
// real container: with the default scheme registered and its handler yielding
// no result, the request reaches the next handler with no authentication result
// on the context and the response stays untouched.
func TestMiddlewareAnonymousRequestPassesThrough(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	provider := godi.GetRequired[auth.SchemeProvider](root)
	require.NoError(t, provider.AddScheme(auth.NewScheme(gois.DefaultCookieAuthenticationScheme, "cookie")))

	scope := root.CreateScope()
	defer scope.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		require.Nil(t, authcore.ResultFromContext(r.Context()), "a no-result authentication must not place a result on the context")
		w.WriteHeader(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(hosting.ContextWithScope(request.Context(), scope))
	response := httptest.NewRecorder()

	authcore.Middleware(provider, logger)(next).ServeHTTP(response, request)

	require.True(t, nextCalled, "the middleware must always invoke the next handler")
	require.Equal(t, http.StatusNoContent, response.Code)
}
