// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"strings"
	"testing"
)

func TestVerifyHonorsThePrincipalAlgorithms(t *testing.T) {
	rsaKey := keyFor(t, "RS256", "rsa")
	ecKey := keyFor(t, "ES256", "ec")
	jwks := keySet(t, rsaKey, ecKey)

	t.Run("listed algorithm is accepted", func(t *testing.T) {
		f := newFixture(Options{})
		principal := Principal{ID: "client", Jwks: jwks, SigningAlgorithms: []string{"ES256"}}
		if err := f.verify(principal, ecKey.sign(t, "ES256", f.claims("client"))); err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if calls := f.registry.callCount(); calls != 1 {
			t.Fatalf("registry called %d times, want 1", calls)
		}
	})

	t.Run("algorithm the server accepts but the principal does not list is rejected before any key is read", func(t *testing.T) {
		f := newFixture(Options{})
		// An unreachable key address shows the key source is never asked.
		principal := Principal{ID: "client", JwksUri: "https://127.0.0.1:1/jwks", SigningAlgorithms: []string{"ES256"}}
		mustReject(t, f, f.verify(principal, rsaKey.sign(t, "RS256", f.claims("client"))))
		logs := f.logs.String()
		if !strings.Contains(logs, "reason="+reasonAlgorithm) {
			t.Fatalf("log does not record the algorithm reason: %s", logs)
		}
	})

	t.Run("empty list leaves the server algorithms in charge", func(t *testing.T) {
		f := newFixture(Options{})
		principal := Principal{ID: "client", Jwks: jwks}
		if err := f.verify(principal, rsaKey.sign(t, "RS256", f.claims("client"))); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})

	t.Run("principal list cannot widen the server algorithms", func(t *testing.T) {
		f := newFixture(Options{SigningAlgorithms: []string{"ES256"}})
		principal := Principal{ID: "client", Jwks: jwks, SigningAlgorithms: []string{"RS256"}}
		mustReject(t, f, f.verify(principal, rsaKey.sign(t, "RS256", f.claims("client"))))
	})
}
