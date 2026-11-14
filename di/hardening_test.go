// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"slices"
	"strings"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/clientassertion"
	"github.com/gonewx/wicket/handlers"
	"github.com/gonewx/wicket/validators"
	validators_impl "github.com/gonewx/wicket/validators/impl"
)

func TestHardeningOptionsAreOffByDefault(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	cfg.Freeze()

	if cfg.AsymmetricRequestObjectsRequired() || cfg.ClientCredentialsAuthenticationRequired() {
		t.Fatal("a hardening option is reported declared")
	}
	if cfg.PrivateKeyJwtSigningAlgorithms() != nil {
		t.Fatal("private_key_jwt algorithms reported while the feature is not enabled")
	}
	if _, ok := godi.GetRequired[validators.JwtRequestValidator](root).(*validators_impl.JwtRequestValidator); !ok {
		t.Fatalf("request object validator is %T, want the unwrapped validator", godi.GetRequired[validators.JwtRequestValidator](root))
	}
	if got := heldValidatorType(godi.GetRequired[*handlers.TokenHandler](root), "clientValidator"); strings.Contains(got, "ClientCredentialsAuthentication") {
		t.Fatalf("token handler holds %s", got)
	}
	var nilConfig *ServerConfig
	if nilConfig.AsymmetricRequestObjectsRequired() || nilConfig.ClientCredentialsAuthenticationRequired() || nilConfig.PrivateKeyJwtSigningAlgorithms() != nil {
		t.Fatal("a nil configuration reports a declaration")
	}
}

func TestHardeningOptionsDeclaredAfterTheRootIsBuilt(t *testing.T) {
	root, cfg := newAssertionRoot(t)
	cfg.RequireAsymmetricRequestObjects()
	cfg.RequireAsymmetricRequestObjects()
	cfg.RequireClientCredentialsAuthentication()
	cfg.RequireClientCredentialsAuthentication()
	cfg.Freeze()

	if !cfg.AsymmetricRequestObjectsRequired() || !cfg.ClientCredentialsAuthenticationRequired() {
		t.Fatal("a declared hardening option is not reported")
	}
	decorator, ok := godi.GetRequired[validators.JwtRequestValidator](root).(*validators_impl.AsymmetricRequestObjectValidator)
	if !ok {
		t.Fatalf("request object validator is %T, want the asymmetric decorator", godi.GetRequired[validators.JwtRequestValidator](root))
	}
	if _, ok := decorator.Inner().(*validators_impl.JwtRequestValidator); !ok {
		t.Fatalf("decorator wraps %T", decorator.Inner())
	}
	if got := heldValidatorType(godi.GetRequired[*handlers.TokenHandler](root), "clientValidator"); got != "*impl.ClientCredentialsAuthenticationValidator" {
		t.Fatalf("token handler holds %s, want the client_credentials wrapper outermost", got)
	}
	// Only the token endpoint is wrapped.
	for name, held := range resolveAuthenticatingHandlers(root) {
		if name != "token" && strings.Contains(held, "ClientCredentialsAuthentication") {
			t.Fatalf("%s handler holds %s", name, held)
		}
	}
}

func TestHardeningOptionsPanicAfterFreeze(t *testing.T) {
	cases := map[string]func(*ServerConfig){
		"RequireAsymmetricRequestObjects":        (*ServerConfig).RequireAsymmetricRequestObjects,
		"RequireClientCredentialsAuthentication": (*ServerConfig).RequireClientCredentialsAuthentication,
	}
	for name, declare := range cases {
		t.Run(name, func(t *testing.T) {
			_, cfg := newAssertionRoot(t)
			cfg.Freeze()
			text := panicText(t, func() { declare(cfg) })
			if !strings.Contains(text, name) || !strings.Contains(text, "after Freeze") {
				t.Fatalf("panic text %q", text)
			}
		})
	}
}

func TestPrivateKeyJwtSigningAlgorithmsAreCopies(t *testing.T) {
	_, cfg := newAssertionRoot(t)
	cfg.EnablePrivateKeyJwt(clientassertion.Options{SigningAlgorithms: []string{"ES256", "PS256"}})
	got := cfg.PrivateKeyJwtSigningAlgorithms()
	if !slices.Equal(got, []string{"ES256", "PS256"}) {
		t.Fatalf("algorithms = %v", got)
	}
	got[0] = "HS256"
	if cfg.PrivateKeyJwtSigningAlgorithms()[0] != "ES256" {
		t.Fatal("the returned list aliases the declaration")
	}

	_, defaults := newAssertionRoot(t)
	defaults.EnablePrivateKeyJwt(clientassertion.Options{})
	if !slices.Equal(defaults.PrivateKeyJwtSigningAlgorithms(), clientassertion.DefaultOptions().SigningAlgorithms) {
		t.Fatalf("algorithms = %v, want the defaults", defaults.PrivateKeyJwtSigningAlgorithms())
	}
	var features any = defaults
	if _, ok := features.(validators_impl.ClientAssertionAlgorithmFeature); !ok {
		t.Fatal("ServerConfig does not report its private_key_jwt algorithms to client configuration validation")
	}
}
