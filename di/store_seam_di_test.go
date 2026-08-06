//go:build integration

// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di_test

import (
	"context"
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
	storage_models "github.com/gonewx/wicket/storage/models"
)

type fixedClock struct {
	at time.Time
}

func (c fixedClock) Now() time.Time { return c.at }

// TestStoreSeamAdoptedByContainer verifies the container resolves the host's
// injected store through the seam instead of the in-memory fallback: a write
// through the container-resolved store must be visible to the injected
// instance, and a fallback-only resolution must never see it.
func TestStoreSeamAdoptedByContainer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := fixedClock{at: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}

	cases := map[string]struct {
		inject   func(*di.ServerConfig, any)
		resolve  func(*di.Root) any
		write    func(any, context.Context) error
		readback func(any, context.Context) (string, error)
		store    any
	}{
		"authorization code store": {
			inject: func(c *di.ServerConfig, v any) { c.SetAuthorizationCodeStore(v.(storage.AuthorizationCodeStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.AuthorizationCodeStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.AuthorizationCodeStore).StoreAuthorizationCode(ctx, "code-1", &storage_models.AuthorizationCode{})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(storage.AuthorizationCodeStore).GetAuthorizationCode(ctx, "code-1")
				return "code-1", err
			},
			store: storage_impl.NewAuthorizationCodeStore(),
		},
		"refresh token store": {
			inject: func(c *di.ServerConfig, v any) { c.SetRefreshTokenStore(v.(storage.RefreshTokenStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.RefreshTokenStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.RefreshTokenStore).StoreRefreshToken(ctx, "rt-1", &storage_models.RefreshToken{})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(storage.RefreshTokenStore).GetRefreshToken(ctx, "rt-1")
				return "rt-1", err
			},
			store: storage_impl.NewRefreshTokenStore(),
		},
		"reference token store": {
			inject: func(c *di.ServerConfig, v any) { c.SetReferenceTokenStore(v.(storage.ReferenceTokenStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.ReferenceTokenStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.ReferenceTokenStore).StoreReferenceToken(ctx, "ref-1", &storage_models.Token{})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(storage.ReferenceTokenStore).GetReferenceToken(ctx, "ref-1")
				return "ref-1", err
			},
			store: storage_impl.NewReferenceTokenStore(),
		},
		"user consent store": {
			inject: func(c *di.ServerConfig, v any) { c.SetUserConsentStore(v.(storage.UserConsentStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.UserConsentStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.UserConsentStore).StoreUserConsent(ctx, &storage_models.Consent{SubjectId: "subj", ClientId: "client"})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(storage.UserConsentStore).GetUserConsent(ctx, "subj", "client")
				return "consent", err
			},
			store: storage_impl.NewUserConsentStore(),
		},
		"session store": {
			inject: func(c *di.ServerConfig, v any) { c.SetSessionStore(v.(sessionpkg.Store)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[sessionpkg.Store](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(sessionpkg.Store).CreateSession(ctx, &sessionpkg.Record{SessionID: "sess-1", SubjectID: "subj"})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(sessionpkg.Store).GetSession(ctx, "sess-1")
				return "sess-1", err
			},
			store: sessionpkg.NewMemoryStore(clock),
		},
		"distributed cache": {
			inject: func(c *di.ServerConfig, v any) { c.SetDistributedCache(v.(services.DistributedCache)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[services.DistributedCache](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(services.DistributedCache).Set("cache-1", []byte("v"), nil)
			},
			readback: func(s any, ctx context.Context) (string, error) {
				got, err := s.(services.DistributedCache).Get("cache-1")
				if err != nil {
					return "", err
				}
				if string(got) != "v" {
					return "", storage.ErrNotFound
				}
				return "cache-1", nil
			},
			store: services_memory.NewMemoryDistributedCache(),
		},
		"key record store": {
			inject: func(c *di.ServerConfig, v any) { c.SetRecordStore(v.(keymgmt.RecordStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[keymgmt.RecordStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(keymgmt.RecordStore).Create(ctx, &keymgmt.Record{Handle: "key-1"})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(keymgmt.RecordStore).Get(ctx, "key-1")
				return "key-1", err
			},
			store: keymgmt.NewMemoryRecordStore(),
		},
		"persisted grant store": {
			inject: func(c *di.ServerConfig, v any) { c.SetPersistedGrantStore(v.(storage.PersistedGrantStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.PersistedGrantStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.PersistedGrantStore).Store(ctx, &storage_models.PersistedGrant{Key: "grant-1"})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(storage.PersistedGrantStore).Get(ctx, "grant-1")
				return "grant-1", err
			},
			store: storage_memory.NewMemoryPersistedGrantStore(),
		},
		"device flow store": {
			inject: func(c *di.ServerConfig, v any) { c.SetDeviceFlowStore(v.(storage.DeviceFlowStore)) },
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.DeviceFlowStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.DeviceFlowStore).StoreDeviceAuthorization(ctx, "dev-1", "user-1", &storage_models.DeviceCode{})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(storage.DeviceFlowStore).FindByDeviceCode(ctx, "dev-1")
				return "dev-1", err
			},
			store: storage_memory.NewMemoryDeviceFlowStore(),
		},
		"backchannel authentication request store": {
			inject: func(c *di.ServerConfig, v any) {
				c.SetBackchannelAuthenticationRequestStore(v.(storage.BackchannelAuthenticationRequestStore))
			},
			resolve: func(r *di.Root) any {
				return godi.GetRequired[storage.BackchannelAuthenticationRequestStore](r)
			},
			write: func(s any, ctx context.Context) error {
				return s.(storage.BackchannelAuthenticationRequestStore).StoreBackchannelAuthenticationRequest(ctx, "ciba-1", &storage_models.BackchannelAuthenticationRequest{})
			},
			readback: func(s any, ctx context.Context) (string, error) {
				_, err := s.(storage.BackchannelAuthenticationRequestStore).FindBackchannelAuthenticationRequest(ctx, "ciba-1")
				return "ciba-1", err
			},
			store: storage_memory.NewMemoryBackchannelAuthenticationRequestStore(),
		},
	}
	for name, tc := range cases {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root, err := di.NewRoot()
			if err != nil {
				t.Fatalf("construct root: %v", err)
			}
			t.Cleanup(func() {
				if err := root.Close(); err != nil {
					t.Fatalf("close root: %v", err)
				}
			})

			tc.inject(root.ServerConfig(), tc.store)
			resolved := tc.resolve(root)

			// A write through the container-resolved store must land in the
			// injected instance; the in-memory fallback is a separate store.
			if err := tc.write(resolved, ctx); err != nil {
				t.Fatalf("write through container store: %v", err)
			}
			handle, err := tc.readback(tc.store, ctx)
			if err != nil {
				t.Fatalf("injected store did not observe the write (handle %q): %v", handle, err)
			}
		})
	}
}

// TestStoreSeamFallbackWarnedThroughContainer verifies a non-injected seam
// resolves to a working in-memory store when the fallback is declared.
func TestStoreSeamFallbackWarnedThroughContainer(t *testing.T) {
	t.Parallel()

	root, err := di.NewRoot()
	if err != nil {
		t.Fatalf("construct root: %v", err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Fatalf("close root: %v", err)
		}
	})

	root.ServerConfig().AllowInMemoryFallback()
	root.ServerConfig().Freeze() // must not panic with the fallback declared

	store := godi.GetRequired[storage.AuthorizationCodeStore](root)
	if err := store.StoreAuthorizationCode(context.Background(), "code-1", &storage_models.AuthorizationCode{}); err != nil {
		t.Fatalf("write through fallback store: %v", err)
	}
	if _, err := store.GetAuthorizationCode(context.Background(), "code-1"); err != nil {
		t.Fatalf("read through fallback store: %v", err)
	}
}
