// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package auth

import "testing"

// A request-handler scheme opts its handler into the middleware traversal, while
// a plain scheme stays in the default authenticate pass only. The capability is
// carried on the scheme record so the registry — the sole static knowledge
// source — can enumerate request handlers ahead of time.
func TestSchemeConstructorsSetHandlesRequests(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		build       func() *Scheme
		wantHandles bool
	}{
		"request-handler scheme opts in": {
			build:       func() *Scheme { return NewRequestHandlerScheme("Google", "GoogleHandler") },
			wantHandles: true,
		},
		"plain scheme stays out": {
			build:       func() *Scheme { return NewScheme("Cookies", "CookieHandler") },
			wantHandles: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scheme := tc.build()
			if scheme.HandlesRequests != tc.wantHandles {
				t.Fatalf("HandlesRequests = %v, want %v", scheme.HandlesRequests, tc.wantHandles)
			}
		})
	}
}

// The request-handler constructor carries the name and handler type through
// unchanged; only the request-handling capability differs from NewScheme.
func TestNewRequestHandlerSchemeCarriesNameAndType(t *testing.T) {
	t.Parallel()
	scheme := NewRequestHandlerScheme("Google", "GoogleHandler")
	if scheme.Name != "Google" {
		t.Fatalf("Name = %q, want %q", scheme.Name, "Google")
	}
	if scheme.HandlerType != "GoogleHandler" {
		t.Fatalf("HandlerType = %q, want %q", scheme.HandlerType, "GoogleHandler")
	}
}
