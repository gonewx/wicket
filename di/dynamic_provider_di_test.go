//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di_test

import (
	"testing"

	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/dynamicscheme"
)

func TestDynamicProviderServicesResolveFromContainer(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Fatalf("close root: %v", err)
		}
	})

	if store := root.ProviderStore(); store == nil {
		t.Fatal("dynamic provider store did not resolve")
	}
	resolver := root.Ptr_Resolver()
	if resolver == nil {
		t.Fatal("dynamic provider resolver did not resolve")
	}
	// Default options are disabled, so the resolver exposes no dynamic providers.
	if resolver.Enabled() {
		t.Fatal("resolver should be disabled by default")
	}
	if all, err := resolver.All(); err != nil || all != nil {
		t.Fatalf("disabled resolver All = %v, %v, want nil, nil", all, err)
	}
}

func TestDynamicSchemeProviderDefaultOffPassThrough(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Fatalf("close root: %v", err)
		}
	})

	provider := root.NewAuthSchemeProvider()
	if provider == nil {
		t.Fatal("auth scheme provider did not resolve")
	}
	// With the dynamic subsystem disabled the merged view equals the static
	// registry view. No static schemes are configured in the default root, so
	// GetAllSchemes reflects only the (empty) static registry — a directly
	// constructed dynamic store is not consulted.
	store := root.ProviderStore()
	_ = store.PutProvider(&dynamicscheme.Provider{Scheme: "extra", Enabled: true, Protocol: "oidc"})
	if scheme := provider.GetScheme("extra"); scheme != nil {
		t.Fatal("disabled dynamic subsystem must not resolve store providers (pass-through)")
	}
}
