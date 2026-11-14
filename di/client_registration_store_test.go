// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// countingRegistrationStore is a host client registration store: the
// in-memory store, with a count of the client and origin lookups it serves.
type countingRegistrationStore struct {
	*storage_memory.MemoryClientRegistrationStore
	byId     atomic.Int64
	byOrigin atomic.Int64
}

func (s *countingRegistrationStore) FindClientById(ctx context.Context, id string) (*storage_models.Client, error) {
	s.byId.Add(1)
	return s.MemoryClientRegistrationStore.FindClientById(ctx, id)
}

func (s *countingRegistrationStore) FindClientsByAllowedOrigin(ctx context.Context, origin string) ([]*storage_models.Client, error) {
	s.byOrigin.Add(1)
	return s.MemoryClientRegistrationStore.FindClientsByAllowedOrigin(ctx, origin)
}

// registrationOnlyStore implements the writable port without the origin
// lookup.
type registrationOnlyStore struct{}

func (registrationOnlyStore) FindClientById(context.Context, string) (*storage_models.Client, error) {
	return nil, storage.ErrNotFound
}

func (registrationOnlyStore) RegisterClient(context.Context, *storage_models.ClientRegistration) (int, error) {
	return 1, nil
}

func (registrationOnlyStore) FindClientRegistration(context.Context, string) (*storage_models.ClientRegistration, error) {
	return nil, storage.ErrNotFound
}

func (registrationOnlyStore) UpdateClientRegistration(context.Context, *storage_models.ClientRegistration, int) (int, error) {
	return 0, storage.ErrNotFound
}

func (registrationOnlyStore) RemoveClientRegistration(context.Context, string, int) error {
	return storage.ErrNotFound
}

func newCountingRegistrationStore(t *testing.T) *countingRegistrationStore {
	t.Helper()
	store := &countingRegistrationStore{MemoryClientRegistrationStore: storage_memory.NewMemoryClientRegistrationStore()}
	for _, client := range newHostClientStore().clients {
		if _, err := store.RegisterClient(context.Background(), &storage_models.ClientRegistration{Client: client}); err != nil {
			t.Fatalf("RegisterClient(%s): %v", client.ClientId, err)
		}
	}
	return store
}

func TestInjectedClientRegistrationStoreServesClientReadsAndCors(t *testing.T) {
	t.Parallel()

	root := newClientSeamRoot(t)
	host := newCountingRegistrationStore(t)
	cfg := root.ServerConfig()
	cfg.SetClientRegistrationStore(host)
	cfg.AllowInMemoryFallback()
	cfg.Freeze()

	if cfg.ClientStore() != storage.ClientStore(host) {
		t.Fatalf("ClientStore() = %v, want the injected registration store", cfg.ClientStore())
	}
	resolved := godi.GetRequired[storage.ClientStore](root)
	decorator, ok := resolved.(*storage_impl.ValidatingClientStore[storage.ClientStore])
	if !ok {
		t.Fatalf("resolved client store is %T, want the validating decorator", resolved)
	}
	if inner := reflect.ValueOf(decorator).Elem().FieldByName("inner").Elem(); inner.Type() != reflect.TypeOf(host) || inner.Pointer() != reflect.ValueOf(host).Pointer() {
		t.Fatalf("decorator wraps %v, want the injected registration store", inner.Type())
	}

	ctx := context.Background()
	if client, err := resolved.FindClientById(ctx, "good"); err != nil || client.ClientId != "good" {
		t.Fatalf("FindClientById(good) = %v, %v", client, err)
	}
	if host.byId.Load() == 0 {
		t.Fatal("the injected store was not consulted for client reads")
	}
	if _, err := resolved.FindClientById(ctx, "broken"); !errors.Is(err, storage.ErrInvalidClientConfiguration) {
		t.Fatalf("FindClientById(broken) error = %v, want storage.ErrInvalidClientConfiguration", err)
	}

	// A client registered after assembly is visible through the read path.
	late := seamTestClient("late", true, "", "https://late.example")
	if _, err := host.RegisterClient(ctx, &storage_models.ClientRegistration{Client: late}); err != nil {
		t.Fatalf("RegisterClient(late): %v", err)
	}
	if client, err := resolved.FindClientById(ctx, "late"); err != nil || client.ClientId != "late" {
		t.Fatalf("FindClientById(late) = %v, %v", client, err)
	}

	cors := godi.GetRequired[services.CorsPolicyService](root)
	for origin, want := range map[string]bool{
		"https://good.example":     true,
		"https://late.example":     true,
		"https://disabled.example": false,
		"https://broken.example":   false,
		"https://unknown.example":  false,
	} {
		if got := cors.IsOriginAllowed(origin); got != want {
			t.Fatalf("IsOriginAllowed(%q) = %v, want %v", origin, got, want)
		}
	}
	if host.byOrigin.Load() == 0 {
		t.Fatal("CORS decisions did not consult the injected store")
	}
}

func TestClientRegistrationStoreSeamFreezeChecks(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		configure func(*ServerConfig)
		wants     []string
	}{
		"with SetClientStore": {
			configure: func(c *ServerConfig) {
				c.SetClientRegistrationStore(storage_memory.NewMemoryClientRegistrationStore())
				c.SetClientStore(newHostClientStore())
			},
			wants: []string{"client registration store", "SetClientStore"},
		},
		"with SetClients": {
			configure: func(c *ServerConfig) {
				c.SetClients(nil)
				c.SetClientRegistrationStore(storage_memory.NewMemoryClientRegistrationStore())
			},
			wants: []string{"client registration store", "SetClients"},
		},
		"with SetClientsProvider": {
			configure: func(c *ServerConfig) {
				c.SetClientRegistrationStore(storage_memory.NewMemoryClientRegistrationStore())
				c.SetClientsProvider(func() []*storage_models.Client { return nil })
			},
			wants: []string{"client registration store", "SetClientsProvider"},
		},
		"without origin lookup": {
			configure: func(c *ServerConfig) { c.SetClientRegistrationStore(registrationOnlyStore{}) },
			wants:     []string{"client registration store", "ClientOriginLookup"},
		},
		"dependent feature without injection": {
			configure: func(c *ServerConfig) { c.enableClientRegistrationDependentFeature("synthetic") },
			wants:     []string{`"client registration store"`, "required by an enabled feature"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			// The global fallback exempts none of these.
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

func TestClientRegistrationStoreFeatureCondition(t *testing.T) {
	t.Parallel()

	t.Run("condition does not hold", func(t *testing.T) {
		t.Parallel()
		for name, inject := range map[string]bool{"not injected": false, "injected": true} {
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()
			if inject {
				cfg.SetClientRegistrationStore(storage_memory.NewMemoryClientRegistrationStore())
			}
			cfg.Freeze() // must not panic: no dependent feature is enabled
			store, err := cfg.clientRegistrationStoreForFeature()
			if err == nil || store != nil {
				t.Fatalf("%s: clientRegistrationStoreForFeature() = %v, %v; want an error", name, store, err)
			}
			if !strings.Contains(err.Error(), "no feature that depends on it is enabled") {
				t.Fatalf("%s: error %q does not name the missing condition", name, err)
			}
		}
	})

	t.Run("condition holds and store injected", func(t *testing.T) {
		t.Parallel()
		host := storage_memory.NewMemoryClientRegistrationStore()
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.enableClientRegistrationDependentFeature("synthetic")
		cfg.SetClientRegistrationStore(host)
		cfg.Freeze()
		store, err := cfg.clientRegistrationStoreForFeature()
		if err != nil || store != storage.ClientRegistrationStore(host) {
			t.Fatalf("clientRegistrationStoreForFeature() = %v, %v; want the injected store", store, err)
		}
	})

	t.Run("condition holds on an unfrozen configuration without a store", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		cfg.enableClientRegistrationDependentFeature("synthetic")
		if store, err := cfg.clientRegistrationStoreForFeature(); err == nil || store != nil {
			t.Fatalf("clientRegistrationStoreForFeature() = %v, %v; want an error", store, err)
		}
	})

	t.Run("feature record", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		cfg.enableClientRegistrationDependentFeature("b")
		cfg.enableClientRegistrationDependentFeature("a")
		cfg.enableClientRegistrationDependentFeature("b")
		if !slices.Equal(cfg.clientRegistrationDependentFeatures, []string{"b", "a"}) {
			t.Fatalf("features = %v, want [b a]", cfg.clientRegistrationDependentFeatures)
		}
		var absent *ServerConfig
		if absent.clientRegistrationDependentFeatureEnabled("a") || absent.clientRegistrationStoreRequired() {
			t.Fatal("a nil configuration reports a dependent feature")
		}
		if _, err := absent.clientRegistrationStoreForFeature(); err == nil {
			t.Fatal("a nil configuration hands out the writable port")
		}
	})
}

// An injected registration store fills the optional client store seam, and
// the feature-required seam never warns.
func TestClientRegistrationStoreSeamWarnings(t *testing.T) {
	t.Parallel()

	capture := &warnCapture{}
	cfg := NewServerConfig()
	cfg.SetLogger(slog.New(capture))
	cfg.AllowInMemoryFallback()
	cfg.SetAuthorizationParametersMessageStore(nil)
	cfg.SetClientRegistrationStore(storage_memory.NewMemoryClientRegistrationStore())
	cfg.Freeze()
	if got := capture.warned(); len(got) != 0 {
		t.Fatalf("warned seams = %v, want none", got)
	}
}
