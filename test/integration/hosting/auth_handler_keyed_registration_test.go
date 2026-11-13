//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	"github.com/gonewx/wicket/di"
	"github.com/stretchr/testify/require"
)

func newAuthRoot(t *testing.T) *di.Root {
	t.Helper()
	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Fatalf("close root: %v", err)
		}
	})
	return root
}

// TestKeyedHandlerIsTransient covers KR3: resolving the keyed handler for a
// scheme name twice within one scope returns distinct instances.
func TestKeyedHandlerIsTransient(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	scope := root.CreateScope()
	defer scope.Close()

	first := godi.GetRequiredKeyed[auth.Handler](scope, wicket.DefaultCookieAuthenticationScheme)
	second := godi.GetRequiredKeyed[auth.Handler](scope, wicket.DefaultCookieAuthenticationScheme)
	require.NotSame(t, first, second, "keyed handlers must be transient")
}

// TestHandlerProviderCachesWithinScopeIsolatesAcrossScopes covers KR4: the
// handler provider returns the same instance for the same scheme within a scope
// and distinct instances across scopes.
func TestHandlerProviderCachesWithinScopeIsolatesAcrossScopes(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	godi.GetRequired[auth.SchemeProvider](root).AddScheme(auth.NewScheme(wicket.DefaultCookieAuthenticationScheme, "cookie"))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	scopeOne := root.CreateScope()
	defer scopeOne.Close()
	providerOne := godi.GetRequired[auth.HandlerProvider](scopeOne)

	firstA, err := providerOne.GetHandler(request, response, wicket.DefaultCookieAuthenticationScheme)
	require.NoError(t, err)
	require.NotNil(t, firstA)
	firstB, err := providerOne.GetHandler(request, response, wicket.DefaultCookieAuthenticationScheme)
	require.NoError(t, err)
	require.Same(t, firstA, firstB, "same scope same scheme must reuse the cached handler")

	scopeTwo := root.CreateScope()
	defer scopeTwo.Close()
	providerTwo := godi.GetRequired[auth.HandlerProvider](scopeTwo)
	second, err := providerTwo.GetHandler(request, response, wicket.DefaultCookieAuthenticationScheme)
	require.NoError(t, err)
	require.NotSame(t, firstA, second, "distinct scopes must resolve distinct handlers")
}

// TestHandlerProviderMissingSchemeDifferentiation covers KR5: an unregistered
// scheme returns (nil, nil); a registered scheme with no keyed handler returns
// an error naming the scheme.
func TestHandlerProviderMissingSchemeDifferentiation(t *testing.T) {
	t.Parallel()

	root := newAuthRoot(t)
	godi.GetRequired[auth.SchemeProvider](root).AddScheme(auth.NewScheme("no-handler", "custom"))

	scope := root.CreateScope()
	defer scope.Close()
	provider := godi.GetRequired[auth.HandlerProvider](scope)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	got, err := provider.GetHandler(request, response, "unregistered")
	require.NoError(t, err)
	require.Nil(t, got)

	got, err = provider.GetHandler(request, response, "no-handler")
	require.Nil(t, got)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no-handler")
}
