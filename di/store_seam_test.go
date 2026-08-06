// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/models/messages"
	"github.com/gonewx/wicket/services"
	services_memory "github.com/gonewx/wicket/services/memory"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
)

type fixedClock struct {
	at time.Time
}

func (c fixedClock) Now() time.Time { return c.at }

type stubAuthorizationParametersMessageStore struct {
	items  map[string]*messages.Message[url.Values]
	nextID int
}

func newStubAuthorizationParametersMessageStore() *stubAuthorizationParametersMessageStore {
	return &stubAuthorizationParametersMessageStore{items: map[string]*messages.Message[url.Values]{}}
}

func (s *stubAuthorizationParametersMessageStore) Write(ctx context.Context, message *messages.Message[url.Values]) (string, error) {
	s.nextID++
	handle := "h" + string(rune('0'+s.nextID))
	s.items[handle] = message
	return handle, nil
}

func (s *stubAuthorizationParametersMessageStore) Read(ctx context.Context, handle string) (*messages.Message[url.Values], error) {
	return s.items[handle], nil
}

func (s *stubAuthorizationParametersMessageStore) Delete(ctx context.Context, handle string) error {
	delete(s.items, handle)
	return nil
}

func TestServerConfigStoreSeamTrios(t *testing.T) {
	t.Parallel()

	clock := fixedClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}

	cases := map[string]struct {
		provided any
		setter   func(*ServerConfig, any)
		read     func(*ServerConfig) any
	}{
		"authorization code store": {
			provided: storage_impl.NewAuthorizationCodeStore(),
			setter:   func(c *ServerConfig, v any) { c.SetAuthorizationCodeStore(v.(storage.AuthorizationCodeStore)) },
			read:     func(c *ServerConfig) any { return c.AuthorizationCodeStore() },
		},
		"refresh token store": {
			provided: storage_impl.NewRefreshTokenStore(),
			setter:   func(c *ServerConfig, v any) { c.SetRefreshTokenStore(v.(storage.RefreshTokenStore)) },
			read:     func(c *ServerConfig) any { return c.RefreshTokenStore() },
		},
		"reference token store": {
			provided: storage_impl.NewReferenceTokenStore(),
			setter:   func(c *ServerConfig, v any) { c.SetReferenceTokenStore(v.(storage.ReferenceTokenStore)) },
			read:     func(c *ServerConfig) any { return c.ReferenceTokenStore() },
		},
		"user consent store": {
			provided: storage_impl.NewUserConsentStore(),
			setter:   func(c *ServerConfig, v any) { c.SetUserConsentStore(v.(storage.UserConsentStore)) },
			read:     func(c *ServerConfig) any { return c.UserConsentStore() },
		},
		"session store": {
			provided: sessionpkg.NewMemoryStore(clock),
			setter:   func(c *ServerConfig, v any) { c.SetSessionStore(v.(sessionpkg.Store)) },
			read:     func(c *ServerConfig) any { return c.SessionStore() },
		},
		"distributed cache": {
			provided: services_memory.NewMemoryDistributedCache(),
			setter:   func(c *ServerConfig, v any) { c.SetDistributedCache(v.(services.DistributedCache)) },
			read:     func(c *ServerConfig) any { return c.DistributedCache() },
		},
		"key record store": {
			provided: keymgmt.NewMemoryRecordStore(),
			setter:   func(c *ServerConfig, v any) { c.SetRecordStore(v.(keymgmt.RecordStore)) },
			read:     func(c *ServerConfig) any { return c.RecordStore() },
		},
		"persisted grant store": {
			provided: storage_memory.NewMemoryPersistedGrantStore(),
			setter:   func(c *ServerConfig, v any) { c.SetPersistedGrantStore(v.(storage.PersistedGrantStore)) },
			read:     func(c *ServerConfig) any { return c.PersistedGrantStore() },
		},
		"device flow store": {
			provided: storage_memory.NewMemoryDeviceFlowStore(),
			setter:   func(c *ServerConfig, v any) { c.SetDeviceFlowStore(v.(storage.DeviceFlowStore)) },
			read:     func(c *ServerConfig) any { return c.DeviceFlowStore() },
		},
		"backchannel authentication request store": {
			provided: storage_memory.NewMemoryBackchannelAuthenticationRequestStore(),
			setter: func(c *ServerConfig, v any) {
				c.SetBackchannelAuthenticationRequestStore(v.(storage.BackchannelAuthenticationRequestStore))
			},
			read: func(c *ServerConfig) any { return c.BackchannelAuthenticationRequestStore() },
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := NewServerConfig()
			if got := tc.read(cfg); got != nil {
				t.Fatalf("unset seam read = %v, want nil", got)
			}

			// Convenience setter form: SetXxxStore(value) must round-trip.
			cfg = NewServerConfig()
			tc.setter(cfg, tc.provided)
			if got := tc.read(cfg); got != tc.provided {
				t.Fatalf("setter form read = %v, want the provided store", got)
			}

			// Provider form: SetXxxStoreProvider(func() T) must be consulted per read.
			cfg = NewServerConfig()
			cfg.SetAuthorizationCodeStoreProvider(func() storage.AuthorizationCodeStore { return nil })
			cfg.SetRefreshTokenStoreProvider(func() storage.RefreshTokenStore { return nil })
			cfg.SetReferenceTokenStoreProvider(func() storage.ReferenceTokenStore { return nil })
			cfg.SetUserConsentStoreProvider(func() storage.UserConsentStore { return nil })
			cfg.SetSessionStoreProvider(func() sessionpkg.Store { return nil })
			cfg.SetDistributedCacheProvider(func() services.DistributedCache { return nil })
			cfg.SetRecordStoreProvider(func() keymgmt.RecordStore { return nil })
			cfg.SetPersistedGrantStoreProvider(func() storage.PersistedGrantStore { return nil })
			cfg.SetDeviceFlowStoreProvider(func() storage.DeviceFlowStore { return nil })
			cfg.SetBackchannelAuthenticationRequestStoreProvider(func() storage.BackchannelAuthenticationRequestStore { return nil })
			if got := tc.read(cfg); got != nil {
				t.Fatalf("provider form read = %v, want nil from the nil-returning provider", got)
			}

			if got := tc.read(nil); got != nil {
				t.Fatalf("nil config read = %v, want nil", got)
			}
		})
	}
}

func TestLazyStoreSeamWarnsAndFallsBack(t *testing.T) {
	t.Parallel()

	clock := fixedClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}

	cases := map[string]struct {
		newWrapper func(cfg *ServerConfig, logger *slog.Logger) func() any
		isMemory   func(any) bool
	}{
		"authorization code store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyAuthorizationCodeStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*storage_impl.AuthorizationCodeStore); return ok },
		},
		"refresh token store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyRefreshTokenStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*storage_impl.RefreshTokenStore); return ok },
		},
		"reference token store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyReferenceTokenStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*storage_impl.ReferenceTokenStore); return ok },
		},
		"user consent store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyUserConsentStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*storage_impl.UserConsentStore); return ok },
		},
		"session store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazySessionStore{cfg: cfg, logger: logger, clock: clock}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*sessionpkg.MemoryStore); return ok },
		},
		"distributed cache": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyDistributedCache{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*services_memory.MemoryDistributedCache); return ok },
		},
		"key record store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyRecordStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*keymgmt.MemoryRecordStore); return ok },
		},
		"persisted grant store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyPersistedGrantStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*storage_memory.MemoryPersistedGrantStore); return ok },
		},
		"device flow store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyDeviceFlowStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*storage_memory.MemoryDeviceFlowStore); return ok },
		},
		"backchannel authentication request store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyBackchannelAuthenticationRequestStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			isMemory: func(v any) bool { _, ok := v.(*storage_memory.MemoryBackchannelAuthenticationRequestStore); return ok },
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			cfg := NewServerConfig()
			cfg.AllowInMemoryFallback()

			impl := tc.newWrapper(cfg, logger)()
			if !tc.isMemory(impl) {
				t.Fatalf("fallback impl = %T, want the in-memory store type", impl)
			}
			logged := buf.String()
			if !strings.Contains(logged, name) {
				t.Fatalf("WARN does not name the store %q; got: %q", name, logged)
			}
			if !strings.Contains(logged, "falling back to in-memory") {
				t.Fatalf("WARN does not describe the fallback; got: %q", logged)
			}
		})
	}
}

func TestLazyStoreSeamUsesInjectedStoreWithoutWarn(t *testing.T) {
	t.Parallel()

	clock := fixedClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}

	cases := map[string]struct {
		newWrapper func(cfg *ServerConfig, logger *slog.Logger) func() any
		inject     func(*ServerConfig)
	}{
		"authorization code store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyAuthorizationCodeStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetAuthorizationCodeStore(storage_impl.NewAuthorizationCodeStore()) },
		},
		"refresh token store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyRefreshTokenStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetRefreshTokenStore(storage_impl.NewRefreshTokenStore()) },
		},
		"reference token store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyReferenceTokenStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetReferenceTokenStore(storage_impl.NewReferenceTokenStore()) },
		},
		"user consent store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyUserConsentStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetUserConsentStore(storage_impl.NewUserConsentStore()) },
		},
		"session store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazySessionStore{cfg: cfg, logger: logger, clock: clock}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetSessionStore(sessionpkg.NewMemoryStore(clock)) },
		},
		"distributed cache": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyDistributedCache{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetDistributedCache(services_memory.NewMemoryDistributedCache()) },
		},
		"key record store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyRecordStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetRecordStore(keymgmt.NewMemoryRecordStore()) },
		},
		"persisted grant store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyPersistedGrantStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetPersistedGrantStore(storage_memory.NewMemoryPersistedGrantStore()) },
		},
		"device flow store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyDeviceFlowStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) { c.SetDeviceFlowStore(storage_memory.NewMemoryDeviceFlowStore()) },
		},
		"backchannel authentication request store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() any {
				w := &lazyBackchannelAuthenticationRequestStore{cfg: cfg, logger: logger}
				return func() any { return w.store() }
			},
			inject: func(c *ServerConfig) {
				c.SetBackchannelAuthenticationRequestStore(storage_memory.NewMemoryBackchannelAuthenticationRequestStore())
			},
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))
			cfg := NewServerConfig()
			tc.inject(cfg)

			tc.newWrapper(cfg, logger)()
			if logged := buf.String(); logged != "" {
				t.Fatalf("injected store must not log a fallback WARN; got: %q", logged)
			}
		})
	}
}

func TestLazyStoreSeamFailsFastWhenFrozenWithoutFallback(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		newWrapper func(cfg *ServerConfig, logger *slog.Logger) func()
	}{
		"authorization code store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyAuthorizationCodeStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"refresh token store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyRefreshTokenStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"reference token store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyReferenceTokenStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"user consent store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyUserConsentStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"session store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazySessionStore{cfg: cfg, logger: logger, clock: fixedClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}}
				return func() { w.store() }
			},
		},
		"distributed cache": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyDistributedCache{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"key record store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyRecordStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"persisted grant store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyPersistedGrantStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"device flow store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyDeviceFlowStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
		"backchannel authentication request store": {
			newWrapper: func(cfg *ServerConfig, logger *slog.Logger) func() {
				w := &lazyBackchannelAuthenticationRequestStore{cfg: cfg, logger: logger}
				return func() { w.store() }
			},
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Freeze() itself fails assembly when a seam is missing, so reach the
			// wrapper-level guard with a directly-frozen config (defense in depth).
			cfg := NewServerConfig()
			cfg.frozen = true
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("store() must fail fast when the config is frozen and no fallback is declared")
				}
				if msg, ok := r.(string); !ok || !strings.Contains(msg, name) {
					t.Fatalf("panic = %v, want it to name the store %q", r, name)
				}
			}()
			tc.newWrapper(cfg, nil)()
		})
	}
}

func TestServerConfigFreezeRequiresInjectedStores(t *testing.T) {
	t.Parallel()

	clock := fixedClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}

	injectAll := func(cfg *ServerConfig) {
		cfg.SetAuthorizationParametersMessageStore(newStubAuthorizationParametersMessageStore())
		cfg.SetPersistedGrantStore(storage_memory.NewMemoryPersistedGrantStore())
		cfg.SetDeviceFlowStore(storage_memory.NewMemoryDeviceFlowStore())
		cfg.SetBackchannelAuthenticationRequestStore(storage_memory.NewMemoryBackchannelAuthenticationRequestStore())
		cfg.SetAuthorizationCodeStore(storage_impl.NewAuthorizationCodeStore())
		cfg.SetRefreshTokenStore(storage_impl.NewRefreshTokenStore())
		cfg.SetReferenceTokenStore(storage_impl.NewReferenceTokenStore())
		cfg.SetUserConsentStore(storage_impl.NewUserConsentStore())
		cfg.SetSessionStore(sessionpkg.NewMemoryStore(clock))
		cfg.SetDistributedCache(services_memory.NewMemoryDistributedCache())
		cfg.SetRecordStore(keymgmt.NewMemoryRecordStore())
	}

	t.Run("all injected", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		injectAll(cfg)
		cfg.Freeze() // must not panic
		if !cfg.Frozen() {
			t.Fatal("Freeze must mark the config frozen")
		}
	})

	t.Run("fallback declared", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.Freeze() // must not panic
	})

	for _, seam := range []struct {
		name  string
		unset func(*ServerConfig)
	}{
		{"authorization parameters message store", func(c *ServerConfig) { c.authorizationParametersMessageStoreProvider = nil }},
		{"persisted grant store", func(c *ServerConfig) { c.persistedGrantStoreProvider = nil }},
		{"device flow store", func(c *ServerConfig) { c.deviceFlowStoreProvider = nil }},
		{"backchannel authentication request store", func(c *ServerConfig) { c.backchannelAuthenticationRequestStoreProvider = nil }},
		{"authorization code store", func(c *ServerConfig) { c.authorizationCodeStoreProvider = nil }},
		{"refresh token store", func(c *ServerConfig) { c.refreshTokenStoreProvider = nil }},
		{"reference token store", func(c *ServerConfig) { c.referenceTokenStoreProvider = nil }},
		{"user consent store", func(c *ServerConfig) { c.userConsentStoreProvider = nil }},
		{"session store", func(c *ServerConfig) { c.sessionStoreProvider = nil }},
		{"distributed cache", func(c *ServerConfig) { c.distributedCacheProvider = nil }},
		{"key record store", func(c *ServerConfig) { c.recordStoreProvider = nil }},
	} {
		seam := seam
		t.Run("missing "+seam.name, func(t *testing.T) {
			t.Parallel()
			cfg := NewServerConfig()
			injectAll(cfg)
			seam.unset(cfg)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("Freeze must fail when the %s seam is missing", seam.name)
				}
				if msg, ok := r.(string); !ok || !strings.Contains(msg, seam.name) {
					t.Fatalf("panic = %v, want it to name the missing store %q", r, seam.name)
				}
			}()
			cfg.Freeze()
		})
	}

	t.Run("mixed injection without declaration", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		cfg.SetAuthorizationCodeStore(storage_impl.NewAuthorizationCodeStore())
		cfg.SetDistributedCache(services_memory.NewMemoryDistributedCache())
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("Freeze must fail on mixed injection without the fallback declaration")
			}
		}()
		cfg.Freeze()
	})
}

func TestLazySessionStoreFallbackUsesInjectedClock(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	clock := fixedClock{at: at}
	cfg := NewServerConfig()
	cfg.AllowInMemoryFallback()
	w := &lazySessionStore{cfg: cfg, logger: nil, clock: clock}

	store := w.store()
	rec := &sessionpkg.Record{
		SessionID:   "s1",
		SubjectID:   "subj",
		DisplayName: "tester",
		Created:     at,
		Renewed:     at,
	}
	if err := store.CreateSession(context.Background(), rec); err != nil {
		t.Fatalf("create session: %v", err)
	}
	got, err := store.GetSession(context.Background(), "s1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.SubjectID != "subj" {
		t.Fatalf("session subject = %q, want %q", got.SubjectID, "subj")
	}
}

func TestLazyDistributedCacheFallbackSharedAcrossResolutions(t *testing.T) {
	t.Parallel()

	cfg := NewServerConfig()
	cfg.AllowInMemoryFallback()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	// The container registers one singleton wrapper; repeated resolutions of the
	// same instance must observe the same fallback store.
	w := &lazyDistributedCache{cfg: cfg, logger: logger}
	if err := w.Set("device:code", []byte("ts"), nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := w.Get("device:code")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != "ts" {
		t.Fatalf("cache value = %q, want the value written through the same wrapper", got)
	}
}
