// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package hosting

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gonewx/godi"
)

// countingProvider is a minimal godi.Provider that records how many child scopes
// it opens, so a test can assert the middleware's per-request scope lifecycle.
type countingProvider struct {
	created int
	scopes  []*countingScope
}

func (p *countingProvider) GetService(reflect.Type) any              { return nil }
func (p *countingProvider) IsService(reflect.Type) bool              { return false }
func (p *countingProvider) IsKeyedService(reflect.Type, any) bool    { return false }
func (p *countingProvider) GetKeyedService(reflect.Type, any) any    { return nil }
func (p *countingProvider) GetKeyedServices(reflect.Type, any) []any { return nil }
func (p *countingProvider) Close() error                             { return nil }
func (p *countingProvider) CreateScope() godi.Scope {
	s := &countingScope{}
	p.created++
	p.scopes = append(p.scopes, s)
	return s
}

type countingScope struct {
	closed bool
}

func (s *countingScope) GetService(reflect.Type) any              { return nil }
func (s *countingScope) IsService(reflect.Type) bool              { return false }
func (s *countingScope) IsKeyedService(reflect.Type, any) bool    { return false }
func (s *countingScope) GetKeyedService(reflect.Type, any) any    { return nil }
func (s *countingScope) GetKeyedServices(reflect.Type, any) []any { return nil }
func (s *countingScope) CreateScope() godi.Scope                  { return s }
func (s *countingScope) Close() error                             { s.closed = true; return nil }

// TestScopeMiddlewareOpensChildScopePerRequest verifies the middleware opens a
// distinct child scope for each request (never the shared root), exposes it via
// ScopeFrom, and closes it once the request completes. A per-request scope is
// what keeps request-scoped services — the authentication handler provider among
// them — from leaking a cached handler's bound request across requests.
func TestScopeMiddlewareOpensChildScopePerRequest(t *testing.T) {
	t.Parallel()

	root := &countingProvider{}

	var seen []godi.Provider
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, ScopeFrom(r.Context()))
	})
	handler := ScopeMiddleware(root)(downstream)

	for range 2 {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	if root.created != 2 {
		t.Fatalf("CreateScope calls = %d, want 2 (one per request)", root.created)
	}
	if len(seen) != 2 {
		t.Fatalf("downstream saw %d scopes, want 2", len(seen))
	}
	for i, sc := range seen {
		if sc == godi.Provider(root) {
			t.Fatalf("request %d saw the root provider; each request must get a child scope", i)
		}
	}
	if seen[0] == seen[1] {
		t.Fatalf("both requests saw the same scope; each request must get a fresh one")
	}
	for i, sc := range root.scopes {
		if !sc.closed {
			t.Fatalf("scope %d was not closed after the request completed", i)
		}
	}
}
