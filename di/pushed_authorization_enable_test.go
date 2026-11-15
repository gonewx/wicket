// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/gonewx/wicket/pushedauth"
	"github.com/gonewx/wicket/storage"
	storage_memory "github.com/gonewx/wicket/storage/memory"
	storage_models "github.com/gonewx/wicket/storage/models"
)

func TestEnablePushedAuthorizationRequests(t *testing.T) {
	t.Parallel()

	t.Run("disabled by default", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		if cfg.PushedAuthorizationRequestsEnabled() {
			t.Fatal("enabled without a declaration")
		}
		if options := cfg.PushedAuthorizationRequestsOptions(); options != (pushedauth.Options{}) {
			t.Fatalf("options = %+v while disabled", options)
		}
	})
	t.Run("enables with defaults", func(t *testing.T) {
		t.Parallel()
		cfg := NewServerConfig()
		cfg.EnablePushedAuthorizationRequests(pushedauth.Options{RequireForAllClients: true})
		if !cfg.PushedAuthorizationRequestsEnabled() || !cfg.pushedAuthorizationRequired() {
			t.Fatal("not enabled")
		}
		options := cfg.PushedAuthorizationRequestsOptions()
		if options.RequestUriLifetime != 60*time.Second || options.InteractionGracePeriod != 10*time.Minute || !options.RequireForAllClients {
			t.Fatalf("options = %+v", options)
		}
	})
	t.Run("negative duration panics", func(t *testing.T) {
		t.Parallel()
		for name, options := range map[string]pushedauth.Options{
			"lifetime": {RequestUriLifetime: -time.Second},
			"grace":    {InteractionGracePeriod: -time.Second},
		} {
			func() {
				defer func() {
					if recover() == nil {
						t.Errorf("%s: no panic", name)
					}
				}()
				NewServerConfig().EnablePushedAuthorizationRequests(options)
			}()
		}
	})
	t.Run("after Freeze panics", func(t *testing.T) {
		t.Parallel()
		cfg := pushedAuthorizationConfig()
		cfg.Freeze()
		defer func() {
			if recover() == nil {
				t.Fatal("no panic")
			}
		}()
		cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
	})
	t.Run("seams become required", func(t *testing.T) {
		t.Parallel()
		cfg := pushedAuthorizationConfig()
		cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
		defer func() {
			if recover() == nil {
				t.Fatal("Freeze accepted an enabled feature without its seams")
			}
		}()
		cfg.Freeze()
	})
	t.Run("service is built over the seams", func(t *testing.T) {
		t.Parallel()
		cfg := pushedAuthorizationConfig()
		cfg.SetPushedAuthorizationRequestStore(storage_memory.NewMemoryPushedAuthorizationRequestStore())
		protection := &recordingDataProtectionProvider{}
		cfg.SetPushedAuthorizationDataProtectionProvider(protection)
		cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
		cfg.Freeze()
		clients, _ := storage_memory.NewMemoryClientStore(nil)
		for range 3 {
			if _, err := cfg.pushedAuthorizationService(clients, pushedTestClock{}); err != nil {
				t.Fatalf("pushedAuthorizationService: %v", err)
			}
		}
		if created := protection.created(); len(created) != 1 {
			t.Fatalf("protector created %d times, want once", len(created))
		}
	})
	t.Run("unusable seams fail closed", func(t *testing.T) {
		t.Parallel()
		root, err := NewRoot()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })
		cfg := root.ServerConfig()
		cfg.AllowInMemoryFallback()
		cfg.SetPushedAuthorizationRequestStoreProvider(func() storage.PushedAuthorizationRequestStore { return nil })
		cfg.SetPushedAuthorizationDataProtectionProvider(&recordingDataProtectionProvider{})
		cfg.EnablePushedAuthorizationRequests(pushedauth.Options{})
		cfg.Freeze()

		feature := pushedAuthorizationFromProvider(root)
		if _, ok := feature.(*pushedauth.Service); ok {
			t.Fatal("a service was built over a nil store")
		}
		ctx := context.Background()
		uri := storage.PushedAuthorizationRequestURIPrefix + "x"
		if _, _, err := feature.Resolve(ctx, uri, "c", "", false); err == nil || errors.Is(err, pushedauth.ErrRequestUriInvalid) {
			t.Fatalf("Resolve = %v, want an infrastructure error", err)
		}
		if err := feature.Consume(ctx, uri, "c"); err == nil || errors.Is(err, pushedauth.ErrRequestUriInvalid) || errors.Is(err, pushedauth.ErrRequestUriConsumed) || errors.Is(err, pushedauth.ErrClientRejected) {
			t.Fatalf("Consume = %v, want an infrastructure error", err)
		}
		client := storage_models.NewClient()
		client.ClientId = "c"
		if _, _, err := feature.Push(ctx, client, url.Values{"client_id": {"c"}}); err == nil || errors.Is(err, pushedauth.ErrRequestUriInvalid) {
			t.Fatalf("Push = %v, want an infrastructure error", err)
		}
		if feature.Required(client) {
			t.Fatal("Required for a client without the requirement")
		}
		client.RequirePushedAuthorizationRequests = true
		if !feature.Required(client) {
			t.Fatal("Required ignores the client requirement")
		}
	})
}

type pushedTestClock struct{}

func (pushedTestClock) Now() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }
