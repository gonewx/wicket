// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package e2e_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/godi"

	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	services_memory "github.com/gonewx/wicket/services/memory"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// storeSeamE2EClock is a fixed clock so session records never depend on the
// wall clock.
type storeSeamE2EClock struct {
	at time.Time
}

func (c storeSeamE2EClock) Now() time.Time { return c.at }

// storeSeamE2EMessageStore is a minimal in-memory implementation of the
// authorization parameters message store port for host-injection assertions.
type storeSeamE2EMessageStore struct {
	items map[string]*messages.Message[url.Values]
	next  int
}

func newStoreSeamE2EMessageStore() *storeSeamE2EMessageStore {
	return &storeSeamE2EMessageStore{items: map[string]*messages.Message[url.Values]{}}
}

func (s *storeSeamE2EMessageStore) Write(_ context.Context, message *messages.Message[url.Values]) (string, error) {
	s.next++
	handle := "h" + string(rune('0'+s.next))
	s.items[handle] = message
	return handle, nil
}

func (s *storeSeamE2EMessageStore) Read(_ context.Context, handle string) (*messages.Message[url.Values], error) {
	return s.items[handle], nil
}

func (s *storeSeamE2EMessageStore) Delete(_ context.Context, handle string) error {
	delete(s.items, handle)
	return nil
}

// storeSeamE2EInjection is one host seam: how to set it, how the container
// exposes it, and how to prove a write through the container-resolved store
// lands in the injected instance.
type storeSeamE2EInjection struct {
	set     func(*di.ServerConfig, any)
	resolve func(*di.Root) any
	write   func(any, context.Context) error
	read    func(any, context.Context) error
	store   any
}

// storeSeamE2EInjections enumerates every store seam the composition root
// validates at assembly time.
func storeSeamE2EInjections(clock storeSeamE2EClock) map[string]storeSeamE2EInjection {
	return map[string]storeSeamE2EInjection{
		"authorization parameters message store": {
			set: func(c *di.ServerConfig, v any) {
				c.SetAuthorizationParametersMessageStore(v.(storage.AuthorizationParametersMessageStore))
			},
			resolve: func(r *di.Root) any {
				return r.NewAuthorizationParametersMessageStore()
			},
			write: func(s any, ctx context.Context) error {
				_, err := s.(storage.AuthorizationParametersMessageStore).Write(ctx, messages.NewMessage(url.Values{"a": {"b"}}))
				return err
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.AuthorizationParametersMessageStore).Read(ctx, "h1")
				return err
			},
			store: newStoreSeamE2EMessageStore(),
		},
		"persisted grant store": {
			set: func(c *di.ServerConfig, v any) { c.SetPersistedGrantStore(v.(storage.PersistedGrantStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.PersistedGrantStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.PersistedGrantStore).Store(ctx, &storage_models.PersistedGrant{Key: "grant-1"})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.PersistedGrantStore).Get(ctx, "grant-1")
				return err
			},
			store: storage_memory.NewMemoryPersistedGrantStore(),
		},
		"device flow store": {
			set: func(c *di.ServerConfig, v any) { c.SetDeviceFlowStore(v.(storage.DeviceFlowStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.DeviceFlowStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.DeviceFlowStore).StoreDeviceAuthorization(ctx, "dev-1", "user-1", &storage_models.DeviceCode{})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.DeviceFlowStore).FindByDeviceCode(ctx, "dev-1")
				return err
			},
			store: storage_memory.NewMemoryDeviceFlowStore(),
		},
		"backchannel authentication request store": {
			set: func(c *di.ServerConfig, v any) {
				c.SetBackchannelAuthenticationRequestStore(v.(storage.BackchannelAuthenticationRequestStore))
			},
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.BackchannelAuthenticationRequestStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.BackchannelAuthenticationRequestStore).StoreBackchannelAuthenticationRequest(ctx, "ciba-1", &storage_models.BackchannelAuthenticationRequest{})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.BackchannelAuthenticationRequestStore).FindBackchannelAuthenticationRequest(ctx, "ciba-1")
				return err
			},
			store: storage_memory.NewMemoryBackchannelAuthenticationRequestStore(),
		},
		"authorization code store": {
			set: func(c *di.ServerConfig, v any) { c.SetAuthorizationCodeStore(v.(storage.AuthorizationCodeStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.AuthorizationCodeStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.AuthorizationCodeStore).StoreAuthorizationCode(ctx, "code-1", &storage_models.AuthorizationCode{})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.AuthorizationCodeStore).GetAuthorizationCode(ctx, "code-1")
				return err
			},
			store: storage_impl.NewAuthorizationCodeStore(),
		},
		"refresh token store": {
			set: func(c *di.ServerConfig, v any) { c.SetRefreshTokenStore(v.(storage.RefreshTokenStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.RefreshTokenStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.RefreshTokenStore).StoreRefreshToken(ctx, "rt-1", &storage_models.RefreshToken{})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.RefreshTokenStore).GetRefreshToken(ctx, "rt-1")
				return err
			},
			store: storage_impl.NewRefreshTokenStore(),
		},
		"reference token store": {
			set: func(c *di.ServerConfig, v any) { c.SetReferenceTokenStore(v.(storage.ReferenceTokenStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.ReferenceTokenStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.ReferenceTokenStore).StoreReferenceToken(ctx, "ref-1", &storage_models.Token{})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.ReferenceTokenStore).GetReferenceToken(ctx, "ref-1")
				return err
			},
			store: storage_impl.NewReferenceTokenStore(),
		},
		"user consent store": {
			set: func(c *di.ServerConfig, v any) { c.SetUserConsentStore(v.(storage.UserConsentStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.UserConsentStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.UserConsentStore).StoreUserConsent(ctx, &storage_models.Consent{SubjectId: "subj", ClientId: "client"})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(storage.UserConsentStore).GetUserConsent(ctx, "subj", "client")
				return err
			},
			store: storage_impl.NewUserConsentStore(),
		},
		"session store": {
			set: func(c *di.ServerConfig, v any) { c.SetSessionStore(v.(sessionpkg.Store)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[sessionpkg.Store](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(sessionpkg.Store).CreateSession(ctx, &sessionpkg.Record{SessionID: "sess-1", SubjectID: "subj"})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(sessionpkg.Store).GetSession(ctx, "sess-1")
				return err
			},
			store: sessionpkg.NewMemoryStore(storeSeamE2EClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}),
		},
		"distributed cache": {
			set: func(c *di.ServerConfig, v any) { c.SetDistributedCache(v.(services.DistributedCache)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[services.DistributedCache](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(services.DistributedCache).Set("cache-1", []byte("v"), nil)
			},
			read: func(s any, ctx context.Context) error {
				got, err := s.(services.DistributedCache).Get("cache-1")
				if err != nil {
					return err
				}
				if string(got) != "v" {
					return storage.ErrNotFound
				}
				return nil
			},
			store: services_memory.NewMemoryDistributedCache(),
		},
		"key record store": {
			set: func(c *di.ServerConfig, v any) { c.SetRecordStore(v.(keymgmt.RecordStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[keymgmt.RecordStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(keymgmt.RecordStore).Create(ctx, &keymgmt.Record{Handle: "key-1"})
			},
			read: func(s any, ctx context.Context) error {
				_, err := s.(keymgmt.RecordStore).Get(ctx, "key-1")
				return err
			},
			store: keymgmt.NewMemoryRecordStore(),
		},
	}
}

// injectStoreSeamE2EAll injects every seam except the one named by skip, so a
// host-assembly test can exercise exactly one missing store.
func injectStoreSeamE2EAll(cfg *di.ServerConfig, injections map[string]storeSeamE2EInjection, skip string) {
	for name, tc := range injections {
		if name == skip {
			continue
		}
		tc.set(cfg, tc.store)
	}
}

func storeSeamE2ENewRoot(t *testing.T) *di.Root {
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

// TestStoreSeamFullInjectionAssemblyE2E pins the host assembly contract for a
// fully injected production root: injecting every store seam and freezing the
// configuration must not fail, and each container-resolved store must be the
// host's instance (a write through the container store is visible to the
// injected store, and a read through it succeeds).
func TestStoreSeamFullInjectionAssemblyE2E(t *testing.T) {
	t.Parallel()

	clock := storeSeamE2EClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	injections := storeSeamE2EInjections(clock)

	root := storeSeamE2ENewRoot(t)
	cfg := root.ServerConfig()
	for _, tc := range injections {
		tc.set(cfg, tc.store)
	}
	cfg.Freeze() // must not panic when every seam is injected

	ctx := context.Background()
	for name, tc := range injections {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resolved := tc.resolve(root)
			if err := tc.write(resolved, ctx); err != nil {
				t.Fatalf("write through container store: %v", err)
			}
			if err := tc.read(tc.store, ctx); err != nil {
				t.Fatalf("injected instance did not observe the write: %v", err)
			}
		})
	}
}

// TestStoreSeamMissingInjectionFailsAssemblyE2E pins the fail-fast production
// assembly contract: a frozen configuration with a missing store seam panics
// at assembly time naming the absent store, and mixed injection without the
// fallback declaration fails the same way.
func TestStoreSeamMissingInjectionFailsAssemblyE2E(t *testing.T) {
	t.Parallel()

	clock := storeSeamE2EClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	injections := storeSeamE2EInjections(clock)

	for name := range injections {
		name := name
		t.Run("missing "+name, func(t *testing.T) {
			t.Parallel()

			root := storeSeamE2ENewRoot(t)
			cfg := root.ServerConfig()
			injectStoreSeamE2EAll(cfg, injections, name)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("Freeze must fail when the %q seam is missing", name)
				}
				if msg, ok := r.(string); !ok || !strings.Contains(msg, name) {
					t.Fatalf("panic = %v, want it to name the missing store %q", r, name)
				}
			}()
			cfg.Freeze()
		})
	}

	t.Run("no injection without declaration", func(t *testing.T) {
		t.Parallel()

		root := storeSeamE2ENewRoot(t)
		cfg := root.ServerConfig()
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("Freeze must fail when no store is injected and no fallback is declared")
			}
		}()
		cfg.Freeze()
	})

	t.Run("mixed injection without declaration", func(t *testing.T) {
		t.Parallel()

		root := storeSeamE2ENewRoot(t)
		cfg := root.ServerConfig()
		injections["authorization code store"].set(cfg, storage_impl.NewAuthorizationCodeStore())
		injections["distributed cache"].set(cfg, services_memory.NewMemoryDistributedCache())
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("Freeze must fail on mixed injection without the fallback declaration")
			}
		}()
		cfg.Freeze()
	})
}

// TestStoreSeamFallbackDeclarationAssemblyE2E pins the declared-fallback
// assembly contract: a host that explicitly accepts the in-memory fallback can
// freeze the configuration without injecting any store, and the container
// resolves working in-memory stores for every seam.
func TestStoreSeamFallbackDeclarationAssemblyE2E(t *testing.T) {
	t.Parallel()

	clock := storeSeamE2EClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
	injections := storeSeamE2EInjections(clock)

	root := storeSeamE2ENewRoot(t)
	cfg := root.ServerConfig()
	cfg.AllowInMemoryFallback()
	cfg.Freeze() // must not panic with the fallback declared

	ctx := context.Background()
	for name, tc := range injections {
		tc := tc
		// The authorization parameters message store has no in-memory
		// fallback: its runtime consumption is optional, so a declared
		// fallback serves the remaining store seams only.
		if name == "authorization parameters message store" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resolved := tc.resolve(root)
			if err := tc.write(resolved, ctx); err != nil {
				t.Fatalf("write through fallback store: %v", err)
			}
			if err := tc.read(resolved, ctx); err != nil {
				t.Fatalf("read through fallback store: %v", err)
			}
		})
	}
}
