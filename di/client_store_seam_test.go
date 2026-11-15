// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// hostClientStore is a host client store double that answers both client and
// origin lookups from one map and counts the lookups it serves.
type hostClientStore struct {
	clients   map[string]*storage_models.Client
	originErr error
	calls     atomic.Int64
}

func (s *hostClientStore) FindClientById(_ context.Context, id string) (*storage_models.Client, error) {
	s.calls.Add(1)
	client, ok := s.clients[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return client, nil
}

func (s *hostClientStore) FindClientsByAllowedOrigin(_ context.Context, origin string) ([]*storage_models.Client, error) {
	s.calls.Add(1)
	if s.originErr != nil {
		return nil, s.originErr
	}
	matches := []*storage_models.Client{}
	for _, client := range s.clients {
		for _, allowed := range client.AllowedCorsOrigins {
			if allowed == origin {
				matches = append(matches, client)
			}
		}
	}
	return matches, nil
}

// idOnlyClientStore cannot answer origin lookups.
type idOnlyClientStore struct{}

func (idOnlyClientStore) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, storage.ErrNotFound
}

func seamTestClient(id string, enabled bool, method string, origin string) *storage_models.Client {
	client := storage_models.NewClient()
	client.ClientId = id
	client.Enabled = enabled
	client.TokenEndpointAuthMethod = method
	if origin != "" {
		client.AllowedCorsOrigins = []string{origin}
	}
	return client
}

func newHostClientStore() *hostClientStore {
	return &hostClientStore{clients: map[string]*storage_models.Client{
		"good":     seamTestClient("good", true, "", "https://good.example"),
		"disabled": seamTestClient("disabled", false, "", "https://disabled.example"),
		"broken":   seamTestClient("broken", true, "unsupported-method", "https://broken.example"),
	}}
}

func newClientSeamRoot(t *testing.T) *Root {
	t.Helper()
	root, err := NewRoot()
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestInjectedClientStoreResolvesThroughValidatingDecorator(t *testing.T) {
	t.Parallel()

	root := newClientSeamRoot(t)
	host := newHostClientStore()
	cfg := root.ServerConfig()
	cfg.SetClientStore(host)
	cfg.AllowInMemoryFallback()
	cfg.Freeze()

	if cfg.ClientStore() != host {
		t.Fatalf("ClientStore() = %v, want the injected store", cfg.ClientStore())
	}
	resolved := godi.GetRequired[storage.ClientStore](root)
	if _, ok := resolved.(*storage_impl.ValidatingClientStore[storage.ClientStore]); !ok {
		t.Fatalf("resolved client store is %T, want the validating decorator", resolved)
	}

	ctx := context.Background()
	client, err := resolved.FindClientById(ctx, "good")
	if err != nil || client != host.clients["good"] {
		t.Fatalf("FindClientById(good) = %v, %v; want the injected client", client, err)
	}
	if host.calls.Load() == 0 {
		t.Fatal("the injected store was not consulted")
	}
	if _, err := resolved.FindClientById(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("FindClientById(missing) error = %v, want storage.ErrNotFound", err)
	}
	if _, err := resolved.FindClientById(ctx, "broken"); !errors.Is(err, storage.ErrInvalidClientConfiguration) {
		t.Fatalf("FindClientById(broken) error = %v, want storage.ErrInvalidClientConfiguration", err)
	}
}

func TestInjectedClientStoreDrivesCors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		origin    string
		originErr error
		want      bool
	}{
		"enabled valid client":         {origin: "https://good.example", want: true},
		"disabled client":              {origin: "https://disabled.example"},
		"invalid configuration":        {origin: "https://broken.example"},
		"unknown origin":               {origin: "https://unknown.example"},
		"lookup failure denies origin": {origin: "https://good.example", originErr: errors.New("store down")},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := newClientSeamRoot(t)
			host := newHostClientStore()
			host.originErr = tc.originErr
			cfg := root.ServerConfig()
			cfg.SetClientStore(host)
			cfg.AllowInMemoryFallback()
			cfg.Freeze()

			if got := godi.GetRequired[services.CorsPolicyService](root).IsOriginAllowed(tc.origin); got != tc.want {
				t.Fatalf("IsOriginAllowed(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}
}

// Without an injected store the static list keeps its behavior: the client
// store validates, and CORS matches origins without filtering.
func TestStaticClientsUnchangedWithoutInjectedStore(t *testing.T) {
	t.Parallel()

	root := newClientSeamRoot(t)
	cfg := root.ServerConfig()
	host := newHostClientStore()
	cfg.SetClients([]*storage_models.Client{host.clients["good"], host.clients["disabled"], host.clients["broken"]})
	cfg.AllowInMemoryFallback()
	cfg.Freeze()

	if cfg.ClientStore() != nil {
		t.Fatalf("ClientStore() = %v, want nil", cfg.ClientStore())
	}
	resolved := godi.GetRequired[storage.ClientStore](root)
	if _, ok := resolved.(*storage_impl.ValidatingClientStore[storage.ClientStore]); !ok {
		t.Fatalf("resolved client store is %T, want the validating decorator", resolved)
	}
	if client, err := resolved.FindClientById(context.Background(), "good"); err != nil || client.ClientId != "good" {
		t.Fatalf("FindClientById(good) = %v, %v", client, err)
	}

	cors := godi.GetRequired[services.CorsPolicyService](root)
	for origin, want := range map[string]bool{
		"https://good.example":     true,
		"https://disabled.example": true,
		"https://broken.example":   true,
		"https://unknown.example":  false,
	} {
		if got := cors.IsOriginAllowed(origin); got != want {
			t.Fatalf("IsOriginAllowed(%q) = %v, want %v", origin, got, want)
		}
	}
}

func TestClientStoreSeamFreezeChecks(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure func(*ServerConfig)
		wants     []string
	}{
		"client store with SetClients": {
			configure: func(c *ServerConfig) {
				c.SetClientStore(newHostClientStore())
				c.SetClients(nil)
			},
			wants: []string{"client store", "SetClients"},
		},
		"client store with SetClientsProvider": {
			configure: func(c *ServerConfig) {
				c.SetClientsProvider(func() []*storage_models.Client { return nil })
				c.SetClientStore(newHostClientStore())
			},
			wants: []string{"client store", "SetClients"},
		},
		"client store without origin lookup": {
			configure: func(c *ServerConfig) { c.SetClientStore(idOnlyClientStore{}) },
			wants:     []string{"client store", "ClientOriginLookup"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()
			tc.configure(cfg)
			text := panicText(t, cfg.Freeze)
			for _, want := range tc.wants {
				if !strings.Contains(text, want) {
					t.Fatalf("panic %q does not mention %q", text, want)
				}
			}
		})
	}
}

func TestStoreSeamCategories(t *testing.T) {
	t.Parallel()

	counts := map[storeSeamCategory]int{}
	for _, seam := range NewServerConfig().storeSeams() {
		counts[seam.category]++
		switch seam.name {
		case "authorization parameters message store", "client store":
			if seam.category != storeSeamOptional {
				t.Fatalf("seam %q is %v, want optional", seam.name, seam.category)
			}
		case "client registration store", "pushed authorization request store", "pushed authorization data protection", "dpop nonce key":
			if seam.category != storeSeamFeatureRequired {
				t.Fatalf("seam %q is %v, want feature-required", seam.name, seam.category)
			}
		default:
			if seam.category != storeSeamRequired {
				t.Fatalf("seam %q is %v, want required", seam.name, seam.category)
			}
		}
	}
	if counts[storeSeamOptional] != 2 || counts[storeSeamRequired] != 10 || counts[storeSeamFeatureRequired] != 4 {
		t.Fatalf("category counts = %v, want 2 optional, 10 required, 4 feature-required", counts)
	}
}

func TestValidateStoreSeamsOnSyntheticSeams(t *testing.T) {
	t.Parallel()

	yes := func() bool { return true }
	no := func() bool { return false }
	tests := map[string]struct {
		seam          storeSeam
		allowFallback bool
		panics        bool
	}{
		"required injected":                        {seam: storeSeam{name: "s", injected: yes}},
		"required missing":                         {seam: storeSeam{name: "s", injected: no}, panics: true},
		"required missing with fallback":           {seam: storeSeam{name: "s", injected: no}, allowFallback: true},
		"optional missing":                         {seam: storeSeam{name: "s", category: storeSeamOptional, injected: no}},
		"feature condition holds, injected":        {seam: storeSeam{name: "s", category: storeSeamFeatureRequired, injected: yes, condition: yes}},
		"feature condition holds, missing":         {seam: storeSeam{name: "s", category: storeSeamFeatureRequired, injected: no, condition: yes}, panics: true},
		"feature condition holds, global fallback": {seam: storeSeam{name: "s", category: storeSeamFeatureRequired, injected: no, condition: yes}, allowFallback: true, panics: true},
		"feature condition holds, seam fallback":   {seam: storeSeam{name: "s", category: storeSeamFeatureRequired, injected: no, condition: yes, fallbackDeclared: yes}},
		"feature condition holds, seam fallback not declared": {
			seam: storeSeam{name: "s", category: storeSeamFeatureRequired, injected: no, condition: yes, fallbackDeclared: no}, allowFallback: true, panics: true,
		},
		"feature condition does not hold": {seam: storeSeam{name: "s", category: storeSeamFeatureRequired, injected: no, condition: no}},
		"feature without condition":       {seam: storeSeam{name: "s", category: storeSeamFeatureRequired, injected: no}, panics: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run := func() { validateStoreSeams([]storeSeam{tc.seam}, tc.allowFallback, nil) }
			if !tc.panics {
				run()
				return
			}
			if text := panicText(t, run); !strings.Contains(text, `"s"`) {
				t.Fatalf("panic %q does not name the seam", text)
			}
		})
	}
}

// warnCapture keeps the messages and seam attributes of warning records.
type warnCapture struct {
	mu    sync.Mutex
	seams []string
}

func (c *warnCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *warnCapture) Handle(_ context.Context, record slog.Record) error {
	if record.Level != slog.LevelWarn {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == "seam" {
			c.seams = append(c.seams, attr.Value.String())
		}
		return true
	})
	return nil
}

func (c *warnCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *warnCapture) WithGroup(string) slog.Handler      { return c }

func (c *warnCapture) warned() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.seams...)
}

func TestFreezeWarnsOnceForEachMissingOptionalSeam(t *testing.T) {
	t.Parallel()

	t.Run("both missing", func(t *testing.T) {
		t.Parallel()
		capture := &warnCapture{}
		cfg := NewServerConfig()
		cfg.SetLogger(slog.New(capture))
		cfg.AllowInMemoryFallback()
		cfg.Freeze()
		got := capture.warned()
		if len(got) != 2 || got[0] != "authorization parameters message store" || got[1] != "client store" {
			t.Fatalf("warned seams = %v, want the two optional seams once each", got)
		}
	})

	t.Run("both injected", func(t *testing.T) {
		t.Parallel()
		capture := &warnCapture{}
		cfg := NewServerConfig()
		cfg.SetLogger(slog.New(capture))
		cfg.AllowInMemoryFallback()
		cfg.SetAuthorizationParametersMessageStore(nil)
		cfg.SetClientStore(newHostClientStore())
		cfg.Freeze()
		if got := capture.warned(); len(got) != 0 {
			t.Fatalf("warned seams = %v, want none", got)
		}
	})

	t.Run("no logger", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.Freeze() // must not panic without a logger
	})
}
