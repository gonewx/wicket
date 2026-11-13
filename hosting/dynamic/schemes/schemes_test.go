// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package schemes

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/auth"
	config_options "github.com/gonewx/wicket/config/options"
	"github.com/gonewx/wicket/dynamicscheme"
)

// fakeInner is a controllable static-registry stand-in exposing the eleven
// auth.SchemeProvider methods.
type fakeInner struct {
	all         []*auth.Scheme
	byName      map[string]*auth.Scheme
	defaultAuth *auth.Scheme
	added       []*auth.Scheme
	removed     []string
}

func newFakeInner(schemes ...*auth.Scheme) *fakeInner {
	byName := map[string]*auth.Scheme{}
	for _, s := range schemes {
		byName[s.Name] = s
	}
	var def *auth.Scheme
	if len(schemes) > 0 {
		def = schemes[0]
	}
	return &fakeInner{all: schemes, byName: byName, defaultAuth: def}
}

func (f *fakeInner) GetAllSchemes() []*auth.Scheme              { return f.all }
func (f *fakeInner) GetScheme(name string) *auth.Scheme         { return f.byName[name] }
func (f *fakeInner) GetDefaultAuthenticateScheme() *auth.Scheme { return f.defaultAuth }
func (f *fakeInner) GetDefaultChallengeScheme() *auth.Scheme    { return f.defaultAuth }
func (f *fakeInner) GetDefaultForbidScheme() *auth.Scheme       { return f.defaultAuth }
func (f *fakeInner) GetDefaultSignInScheme() *auth.Scheme       { return f.defaultAuth }
func (f *fakeInner) GetDefaultSignOutScheme() *auth.Scheme      { return f.defaultAuth }
func (f *fakeInner) AddScheme(s *auth.Scheme) error             { f.added = append(f.added, s); return nil }
func (f *fakeInner) TryAddScheme(s *auth.Scheme) bool           { f.added = append(f.added, s); return true }
func (f *fakeInner) RemoveScheme(name string) bool {
	f.removed = append(f.removed, name)
	_, ok := f.byName[name]
	return ok
}
func (f *fakeInner) GetRequestHandlerSchemes() ([]*auth.Scheme, error) {
	var schemes []*auth.Scheme
	for _, s := range f.all {
		if s != nil && s.HandlesRequests {
			schemes = append(schemes, s)
		}
	}
	return schemes, nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// errStore returns an error from AllProviders/GetProvider to exercise the
// degrade-to-static path.
type errStore struct{}

func (errStore) GetProvider(string) (*dynamicscheme.Provider, error) {
	return nil, errors.New("boom")
}
func (errStore) AllProviders() ([]*dynamicscheme.Provider, error) { return nil, errors.New("boom") }
func (errStore) PutProvider(*dynamicscheme.Provider) error        { return nil }
func (errStore) DeleteProvider(string) error                      { return nil }

func enabledResolver(t *testing.T, providers ...*dynamicscheme.Provider) *dynamicscheme.Resolver {
	t.Helper()
	store := dynamicscheme.NewMemoryStore()
	for _, p := range providers {
		if err := store.PutProvider(p); err != nil {
			t.Fatalf("seed store: %v", err)
		}
	}
	return dynamicscheme.NewResolver(store, fixedClock{time.Unix(1_700_000_000, 0)}, true, time.Minute)
}

func decorate(inner auth.SchemeProvider) *wicket.Decorator[auth.SchemeProvider] {
	return wicket.NewDecorator[auth.SchemeProvider](inner)
}

func dynProvider(scheme string, enabled bool) *dynamicscheme.Provider {
	return &dynamicscheme.Provider{Scheme: scheme, Enabled: enabled, Protocol: "oidc"}
}

func TestAuthSchemeProviderDisabledPassThrough(t *testing.T) {
	t.Parallel()

	inner := newFakeInner(auth.NewScheme("static", "cookie"))
	// Enabled=false: resolver present but disabled — must not merge dynamic rows.
	disabled := dynamicscheme.NewResolver(dynamicscheme.NewMemoryStore(), fixedClock{}, false, time.Minute)
	p := NewAuthSchemeProvider(decorate(inner), &config_options.DynamicProviderOptions{Enabled: false}, disabled, nil)

	if got := p.GetScheme("static"); got == nil || got.Name != "static" {
		t.Fatalf("GetScheme(static) = %v, want static", got)
	}
	if got := p.GetScheme("dynamic"); got != nil {
		t.Fatal("disabled provider must not resolve dynamic schemes")
	}
	if all := p.GetAllSchemes(); len(all) != 1 || all[0].Name != "static" {
		t.Fatalf("GetAllSchemes = %v, want [static]", all)
	}
	if got := p.GetDefaultAuthenticateScheme(); got == nil || got.Name != "static" {
		t.Fatal("default authenticate scheme should delegate to inner")
	}
}

func TestAuthSchemeProviderNilInner(t *testing.T) {
	t.Parallel()

	p := NewAuthSchemeProvider(nil, &config_options.DynamicProviderOptions{Enabled: true}, enabledResolver(t), nil)
	if p.GetAllSchemes() != nil {
		t.Fatal("nil inner GetAllSchemes should be nil")
	}
	if p.GetScheme("x") != nil {
		t.Fatal("nil inner GetScheme should be nil")
	}
	if p.GetDefaultAuthenticateScheme() != nil {
		t.Fatal("nil inner default should be nil")
	}
	if p.AddScheme(auth.NewScheme("x", "y")) != nil {
		t.Fatal("nil inner AddScheme should be nil error")
	}
	if p.TryAddScheme(auth.NewScheme("x", "y")) {
		t.Fatal("nil inner TryAddScheme should be false")
	}
	if s, err := p.GetRequestHandlerSchemes(); s != nil || err != nil {
		t.Fatalf("nil inner GetRequestHandlerSchemes = %v,%v", s, err)
	}
}

func TestAuthSchemeProviderEnabledResolution(t *testing.T) {
	t.Parallel()

	inner := newFakeInner(auth.NewScheme("static", "cookie"))
	resolver := enabledResolver(t, dynProvider("dynamic", true), dynProvider("off", false))
	p := NewAuthSchemeProvider(decorate(inner), &config_options.DynamicProviderOptions{Enabled: true}, resolver, nil)

	tests := map[string]struct {
		name string
		want string // "" means nil expected
	}{
		"static hit":            {"static", "static"},
		"dynamic hit on miss":   {"dynamic", "dynamic"},
		"disabled row not seen": {"off", ""},
		"absent":                {"absent", ""},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := p.GetScheme(tt.name)
			if tt.want == "" {
				if got != nil {
					t.Fatalf("GetScheme(%s) = %v, want nil", tt.name, got)
				}
				return
			}
			if got == nil || got.Name != tt.want {
				t.Fatalf("GetScheme(%s) = %v, want %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestAuthSchemeProviderMergeAndConflict(t *testing.T) {
	t.Parallel()

	inner := newFakeInner(auth.NewScheme("static", "cookie"), auth.NewScheme("shared", "cookie"))
	// "shared" also exists dynamically: static must win and not be duplicated.
	resolver := enabledResolver(t, dynProvider("shared", true), dynProvider("adyn", true), dynProvider("zdyn", true))
	p := NewAuthSchemeProvider(decorate(inner), &config_options.DynamicProviderOptions{Enabled: true}, resolver, nil)

	all := p.GetAllSchemes()
	// static first (static, shared), then dynamic in scheme order (adyn, zdyn);
	// shared not duplicated.
	wantOrder := []string{"static", "shared", "adyn", "zdyn"}
	if len(all) != len(wantOrder) {
		t.Fatalf("GetAllSchemes len = %d (%v), want %d", len(all), names(all), len(wantOrder))
	}
	for i, w := range wantOrder {
		if all[i].Name != w {
			t.Fatalf("GetAllSchemes[%d] = %s, want %s (full %v)", i, all[i].Name, w, names(all))
		}
	}
}

func TestAuthSchemeProviderDefaultsIgnoreDynamic(t *testing.T) {
	t.Parallel()

	inner := newFakeInner(auth.NewScheme("static", "cookie"))
	resolver := enabledResolver(t, dynProvider("dynamic", true))
	p := NewAuthSchemeProvider(decorate(inner), &config_options.DynamicProviderOptions{Enabled: true}, resolver, nil)

	for name, got := range map[string]*auth.Scheme{
		"authenticate": p.GetDefaultAuthenticateScheme(),
		"challenge":    p.GetDefaultChallengeScheme(),
		"forbid":       p.GetDefaultForbidScheme(),
		"signin":       p.GetDefaultSignInScheme(),
		"signout":      p.GetDefaultSignOutScheme(),
	} {
		if got == nil || got.Name != "static" {
			t.Fatalf("default %s = %v, want static (dynamic rows must not affect defaults)", name, got)
		}
	}
}

func TestAuthSchemeProviderAddDelegates(t *testing.T) {
	t.Parallel()

	inner := newFakeInner()
	p := NewAuthSchemeProvider(decorate(inner), &config_options.DynamicProviderOptions{Enabled: true}, enabledResolver(t), nil)
	_ = p.AddScheme(auth.NewScheme("a", "cookie"))
	if !p.TryAddScheme(auth.NewScheme("b", "cookie")) {
		t.Fatal("TryAddScheme should delegate to inner and return true")
	}
	if len(inner.added) != 2 {
		t.Fatalf("inner.added = %d, want 2 (AddScheme/TryAddScheme delegate to static registry)", len(inner.added))
	}
}

func TestAuthSchemeProviderResolverErrorDegrades(t *testing.T) {
	t.Parallel()

	inner := newFakeInner(auth.NewScheme("static", "cookie"))
	resolver := dynamicscheme.NewResolver(errStore{}, fixedClock{}, true, time.Minute)
	p := NewAuthSchemeProvider(decorate(inner), &config_options.DynamicProviderOptions{Enabled: true}, resolver, nil)

	// Resolver error must degrade to the static view, not panic or fail.
	if got := p.GetScheme("static"); got == nil {
		t.Fatal("static scheme should still resolve when the resolver errors")
	}
	if got := p.GetScheme("dynamic"); got != nil {
		t.Fatal("dynamic lookup on resolver error should return nil (degrade)")
	}
	if all := p.GetAllSchemes(); len(all) != 1 || all[0].Name != "static" {
		t.Fatalf("GetAllSchemes on resolver error = %v, want [static]", names(all))
	}
}

func TestUseSchemeAuthMiddleware(t *testing.T) {
	t.Parallel()

	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	tests := map[string]struct {
		options  *config_options.DynamicProviderOptions
		sameHTTP bool // disabled returns next unchanged
	}{
		"disabled returns next": {&config_options.DynamicProviderOptions{Enabled: false}, true},
		"nil options no-op":     {nil, true},
		"enabled wraps":         {&config_options.DynamicProviderOptions{Enabled: true}, false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mw := UseSchemeAuthMiddleware(nil, tt.options)
			wrapped := mw(terminal)
			// Behavior: the request still reaches the terminal handler in both states.
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://wicket.test/", nil))
			if rec.Code != http.StatusTeapot {
				t.Fatalf("wrapped handler did not pass through: code %d", rec.Code)
			}
		})
	}
}

func names(schemes []*auth.Scheme) []string {
	out := make([]string, 0, len(schemes))
	for _, s := range schemes {
		out = append(out, s.Name)
	}
	return out
}

func requestHandlerScheme(name string) *auth.Scheme {
	scheme := auth.NewScheme(name, "oidc")
	scheme.HandlesRequests = true
	return scheme
}

func TestAuthSchemeProviderRequestHandlerSchemesSymmetry(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		enabled   bool
		inner     *fakeInner
		resolver  func(t *testing.T) *dynamicscheme.Resolver
		wantNames []string
	}{
		"disabled is pure pass-through of the static view": {
			enabled: false,
			inner:   newFakeInner(requestHandlerScheme("static"), auth.NewScheme("plain", "cookie")),
			resolver: func(t *testing.T) *dynamicscheme.Resolver {
				return dynamicscheme.NewResolver(dynamicscheme.NewMemoryStore(), fixedClock{}, false, time.Minute)
			},
			wantNames: []string{"static"},
		},
		"enabled merges dynamic providers behind the static view": {
			enabled: true,
			inner:   newFakeInner(requestHandlerScheme("static"), auth.NewScheme("plain", "cookie")),
			resolver: func(t *testing.T) *dynamicscheme.Resolver {
				return enabledResolver(t, dynProvider("dynamic", true), dynProvider("off", false))
			},
			wantNames: []string{"static", "dynamic"},
		},
		"static name shadows the dynamic row": {
			enabled: true,
			inner:   newFakeInner(requestHandlerScheme("shared")),
			resolver: func(t *testing.T) *dynamicscheme.Resolver {
				return enabledResolver(t, dynProvider("shared", true), dynProvider("extra", true))
			},
			wantNames: []string{"shared", "extra"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider := NewAuthSchemeProvider(decorate(tc.inner), &config_options.DynamicProviderOptions{Enabled: tc.enabled}, tc.resolver(t), nil)

			schemes, err := provider.GetRequestHandlerSchemes()
			if err != nil {
				t.Fatalf("GetRequestHandlerSchemes error: %v", err)
			}
			got := map[string]bool{}
			for _, scheme := range schemes {
				if !scheme.HandlesRequests {
					t.Fatalf("scheme %s lost its request-handling capability", scheme.Name)
				}
				got[scheme.Name] = true
			}
			if len(got) != len(tc.wantNames) {
				t.Fatalf("GetRequestHandlerSchemes = %v, want %v", names(schemes), tc.wantNames)
			}
			for _, want := range tc.wantNames {
				if !got[want] {
					t.Fatalf("GetRequestHandlerSchemes = %v, missing %s", names(schemes), want)
				}
			}
		})
	}
}

func TestAuthSchemeProviderRequestHandlerSchemesDegradeToStatic(t *testing.T) {
	t.Parallel()

	resolver := dynamicscheme.NewResolver(errStore{}, fixedClock{}, true, time.Minute)
	inner := newFakeInner(requestHandlerScheme("static"))
	provider := NewAuthSchemeProvider(decorate(inner), &config_options.DynamicProviderOptions{Enabled: true}, resolver, nil)

	schemes, err := provider.GetRequestHandlerSchemes()
	if err != nil {
		t.Fatalf("GetRequestHandlerSchemes error: %v", err)
	}
	if len(schemes) != 1 || schemes[0].Name != "static" {
		t.Fatalf("GetRequestHandlerSchemes = %v, want [static]", names(schemes))
	}
}
