// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/gonewx/wicket/di"
	"github.com/gonewx/wicket/keymgmt"
	"github.com/gonewx/wicket/services"
	services_memory "github.com/gonewx/wicket/services/memory"
	sessionpkg "github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_memory "github.com/gonewx/wicket/storage/memory"
)

// rootCloseClock is a fixed time source so session records never depend on
// the wall clock.
type rootCloseClock struct {
	at time.Time
}

func (c rootCloseClock) Now() time.Time { return c.at }

// closeRecorder observes the order in which host adapters are released, so
// the container's LIFO close sequence is asserted on recorded names.
type closeRecorder struct {
	mu    sync.Mutex
	order []string
}

func (l *closeRecorder) record(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.order = append(l.order, name)
}

func (l *closeRecorder) names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.order))
	copy(out, l.order)
	return out
}

// The recording adapter types below wrap an injected store adapter and
// record its release, so a host-owned adapter's lifecycle is observable at
// the composition root. Each embeds one store port and adds io.Closer.
type recordingPersistedGrantStore struct {
	storage.PersistedGrantStore
	name string
	log  *closeRecorder
}

func (a *recordingPersistedGrantStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingDeviceFlowStore struct {
	storage.DeviceFlowStore
	name string
	log  *closeRecorder
}

func (a *recordingDeviceFlowStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingBackchannelStore struct {
	storage.BackchannelAuthenticationRequestStore
	name string
	log  *closeRecorder
}

func (a *recordingBackchannelStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingRecordStore struct {
	keymgmt.RecordStore
	name string
	log  *closeRecorder
}

func (a *recordingRecordStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingDistributedCache struct {
	services.DistributedCache
	name string
	log  *closeRecorder
}

func (a *recordingDistributedCache) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingAuthorizationCodeStore struct {
	storage.AuthorizationCodeStore
	name string
	log  *closeRecorder
}

func (a *recordingAuthorizationCodeStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingRefreshTokenStore struct {
	storage.RefreshTokenStore
	name string
	log  *closeRecorder
}

func (a *recordingRefreshTokenStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingReferenceTokenStore struct {
	storage.ReferenceTokenStore
	name string
	log  *closeRecorder
}

func (a *recordingReferenceTokenStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingUserConsentStore struct {
	storage.UserConsentStore
	name string
	log  *closeRecorder
}

func (a *recordingUserConsentStore) Close() error {
	a.log.record(a.name)
	return nil
}

type recordingSessionStore struct {
	sessionpkg.Store
	name string
	log  *closeRecorder
}

func (a *recordingSessionStore) Close() error {
	a.log.record(a.name)
	return nil
}

// rootCloseSeam is one injectable store seam plus the materialization call
// that forces the lazy wrapper to read the seam.
type rootCloseSeam struct {
	name    string
	adapter any
	set     func(*di.ServerConfig, any)
	use     func(*di.Root, context.Context)
}

// rootCloseSeams enumerates every container-managed store seam. The order of
// the expected LIFO release follows the Track sequence in the generated
// NewRoot: persist -> device -> backchannel -> record -> cache -> code ->
// refresh -> reference -> consent -> session, released in reverse.
func rootCloseSeams(recorder *closeRecorder) map[string]rootCloseSeam {
	return map[string]rootCloseSeam{
		"persisted grant store": {
			name:    "persisted grant store",
			adapter: &recordingPersistedGrantStore{PersistedGrantStore: storage_memory.NewMemoryPersistedGrantStore(), name: "persisted grant store", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetPersistedGrantStore(v.(storage.PersistedGrantStore)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[storage.PersistedGrantStore](r).Get(ctx, "missing")
			},
		},
		"device flow store": {
			name:    "device flow store",
			adapter: &recordingDeviceFlowStore{DeviceFlowStore: storage_memory.NewMemoryDeviceFlowStore(), name: "device flow store", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetDeviceFlowStore(v.(storage.DeviceFlowStore)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[storage.DeviceFlowStore](r).FindByDeviceCode(ctx, "missing")
			},
		},
		"backchannel authentication request store": {
			name: "backchannel authentication request store",
			adapter: &recordingBackchannelStore{
				BackchannelAuthenticationRequestStore: storage_memory.NewMemoryBackchannelAuthenticationRequestStore(),
				name:                                  "backchannel authentication request store",
				log:                                   recorder,
			},
			set: func(c *di.ServerConfig, v any) {
				c.SetBackchannelAuthenticationRequestStore(v.(storage.BackchannelAuthenticationRequestStore))
			},
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[storage.BackchannelAuthenticationRequestStore](r).FindBackchannelAuthenticationRequest(ctx, "missing")
			},
		},
		"key record store": {
			name:    "key record store",
			adapter: &recordingRecordStore{RecordStore: keymgmt.NewMemoryRecordStore(), name: "key record store", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetRecordStore(v.(keymgmt.RecordStore)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[keymgmt.RecordStore](r).Get(ctx, "missing")
			},
		},
		"distributed cache": {
			name:    "distributed cache",
			adapter: &recordingDistributedCache{DistributedCache: services_memory.NewMemoryDistributedCache(), name: "distributed cache", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetDistributedCache(v.(services.DistributedCache)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[services.DistributedCache](r).Get("missing")
			},
		},
		"authorization code store": {
			name:    "authorization code store",
			adapter: &recordingAuthorizationCodeStore{AuthorizationCodeStore: storage_impl.NewAuthorizationCodeStore(), name: "authorization code store", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetAuthorizationCodeStore(v.(storage.AuthorizationCodeStore)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[storage.AuthorizationCodeStore](r).GetAuthorizationCode(ctx, "missing")
			},
		},
		"refresh token store": {
			name:    "refresh token store",
			adapter: &recordingRefreshTokenStore{RefreshTokenStore: storage_impl.NewRefreshTokenStore(), name: "refresh token store", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetRefreshTokenStore(v.(storage.RefreshTokenStore)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[storage.RefreshTokenStore](r).GetRefreshToken(ctx, "missing")
			},
		},
		"reference token store": {
			name:    "reference token store",
			adapter: &recordingReferenceTokenStore{ReferenceTokenStore: storage_impl.NewReferenceTokenStore(), name: "reference token store", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetReferenceTokenStore(v.(storage.ReferenceTokenStore)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[storage.ReferenceTokenStore](r).GetReferenceToken(ctx, "missing")
			},
		},
		"user consent store": {
			name:    "user consent store",
			adapter: &recordingUserConsentStore{UserConsentStore: storage_impl.NewUserConsentStore(), name: "user consent store", log: recorder},
			set:     func(c *di.ServerConfig, v any) { c.SetUserConsentStore(v.(storage.UserConsentStore)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[storage.UserConsentStore](r).GetUserConsent(ctx, "subj", "client")
			},
		},
		"session store": {
			name: "session store",
			adapter: &recordingSessionStore{
				Store: sessionpkg.NewMemoryStore(rootCloseClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}),
				name:  "session store",
				log:   recorder,
			},
			set: func(c *di.ServerConfig, v any) { c.SetSessionStore(v.(sessionpkg.Store)) },
			use: func(r *di.Root, ctx context.Context) {
				_, _ = godi.GetRequired[sessionpkg.Store](r).GetSession(ctx, "missing")
			},
		},
	}
}

// TestRootCloseReleasesMaterializedClosableAdapters verifies that closing the
// root releases every materialized host adapter that implements io.Closer,
// exactly once, in LIFO (reverse-construction) order.
func TestRootCloseReleasesMaterializedClosableAdapters(t *testing.T) {
	t.Parallel()

	recorder := &closeRecorder{}
	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	cfg := root.ServerConfig()
	for _, tc := range rootCloseSeams(recorder) {
		tc.set(cfg, tc.adapter)
	}
	ctx := context.Background()
	for _, tc := range rootCloseSeams(recorder) {
		tc.use(root, ctx)
	}

	if err := root.Close(); err != nil {
		t.Fatalf("close root: %v", err)
	}

	want := []string{
		"session store",
		"user consent store",
		"reference token store",
		"refresh token store",
		"authorization code store",
		"distributed cache",
		"key record store",
		"backchannel authentication request store",
		"device flow store",
		"persisted grant store",
	}
	if got := recorder.names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("close order = %v, want LIFO %v", got, want)
	}
}

// TestRootCloseUnmaterializedSeamsNoFallbackWarn verifies that closing an
// unmaterialized seam is a no-op: it returns nil, never reads the seam, and
// never emits the in-memory fallback warning.
func TestRootCloseUnmaterializedSeamsNoFallbackWarn(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("close root with unmaterialized seams: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := di.NewServerConfig()
	cfg.AllowInMemoryFallback()
	closer := di.NewlazyPersistedGrantStore(cfg, logger)
	if err := closer.Close(); err != nil {
		t.Fatalf("close unmaterialized wrapper: %v", err)
	}
	if logged := buf.String(); logged != "" {
		t.Fatalf("unmaterialized close logged a fallback warning: %q", logged)
	}
}

// TestRootCloseIdempotent verifies that a second Close returns the cached
// result of the first and does not release adapters a second time.
func TestRootCloseIdempotent(t *testing.T) {
	t.Parallel()

	recorder := &closeRecorder{}
	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	cfg := root.ServerConfig()
	seams := rootCloseSeams(recorder)
	seams["persisted grant store"].set(cfg, seams["persisted grant store"].adapter)
	seams["persisted grant store"].use(root, context.Background())

	first := root.Close()
	second := root.Close()
	if first != nil || second != nil {
		t.Fatalf("close results = (%v, %v), want (nil, nil)", first, second)
	}
	if got := recorder.names(); len(got) != 1 || got[0] != "persisted grant store" {
		t.Fatalf("adapter released %d times (%v), want exactly once", len(got), got)
	}
}

// TestRootResolveAfterClosePanicsProviderClosed verifies that resolving any
// service after Close panics with godi.ErrProviderClosed.
func TestRootResolveAfterClosePanicsProviderClosed(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("close root: %v", err)
	}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("resolve after close did not panic")
		}
		if err, ok := r.(error); !ok || !errors.Is(err, godi.ErrProviderClosed) {
			t.Fatalf("panic = %v, want godi.ErrProviderClosed", r)
		}
	}()
	_ = godi.GetRequired[storage.PersistedGrantStore](root)
}

// TestRootCloseWithInMemoryFallbackNoPanic verifies that the declared
// in-memory fallback path closes cleanly: a fallback store has no Close
// method, so the release is a no-op and Close returns nil without panicking.
func TestRootCloseWithInMemoryFallbackNoPanic(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	root.ServerConfig().AllowInMemoryFallback()
	root.ServerConfig().Freeze()

	store := godi.GetRequired[storage.AuthorizationCodeStore](root)
	if err := store.StoreAuthorizationCode(context.Background(), "code-1", nil); err != nil {
		t.Fatalf("write through fallback store: %v", err)
	}

	if err := root.Close(); err != nil {
		t.Fatalf("close root over fallback stores: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("second close over fallback stores: %v", err)
	}
}

// nonCloserAdapter implements a store port with a Close method that does not
// return an error, so the type is NOT an io.Closer and the container must
// leave it unreleased.
type nonCloserAdapter struct {
	storage.PersistedGrantStore
	closed bool
}

func (a *nonCloserAdapter) Close() { a.closed = true }

// TestRootCloseSkipsNonCloserAdapters verifies that an adapter without the
// io.Closer shape is left untouched by Close.
func TestRootCloseSkipsNonCloserAdapters(t *testing.T) {
	t.Parallel()

	adapter := &nonCloserAdapter{PersistedGrantStore: storage_memory.NewMemoryPersistedGrantStore()}
	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	root.ServerConfig().SetPersistedGrantStore(adapter)
	_, _ = godi.GetRequired[storage.PersistedGrantStore](root).Get(context.Background(), "missing")

	if err := root.Close(); err != nil {
		t.Fatalf("close root: %v", err)
	}
	if adapter.closed {
		t.Fatal("non-Closer adapter was released by the container")
	}
}
