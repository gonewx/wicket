// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/storage"
	"github.com/gonewx/wicket/storage/models"
)

// clientRegistrationConcurrency is how many goroutines race in the
// concurrent registration and update cases.
const clientRegistrationConcurrency = 16

// RunClientRegistrationStoreSuite runs the conformance suite for a
// storage.ClientRegistrationStore. newStore must return a fresh empty store on
// each call. The store must also implement storage.ClientOriginLookup on the
// same data; the suite fails a store that does not.
func RunClientRegistrationStoreSuite(t *testing.T, newStore func() storage.ClientRegistrationStore, opts ...Option) {
	t.Helper()
	cfg := newOptions(opts)

	mustCase(t, "ContextCancellationReadMiss", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.FindClientRegistration(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
		_, err = store.FindClientById(cancelledContext(), "missing")
		assertCancellationReadMiss(t, err)
	})
	mustCase(t, "ContextCancellationWrite", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.RegisterClient(cancelledContext(), newClientRegistration("client-a"))
		assertCancellationWrite(t, err, func() error {
			_, getErr := store.FindClientRegistration(context.Background(), "client-a")
			return getErr
		})
	})
	mustCase(t, "MissingReadReturnsSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		registration, err := store.FindClientRegistration(context.Background(), "missing")
		if registration != nil {
			t.Fatalf("FindClientRegistration(missing) = %v, want nil record with sentinel", registration)
		}
		expectNotFound(t, err)
		client, err := store.FindClientById(context.Background(), "missing")
		if client != nil {
			t.Fatalf("FindClientById(missing) = %v, want nil record with sentinel", client)
		}
		expectNotFound(t, err)
	})
	mustCase(t, "RegisterRoundTrip", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		registration := newClientRegistration("client-a")
		// The store assigns revisions: the value passed in is ignored.
		registration.Revision = 42
		revision, err := store.RegisterClient(context.Background(), registration)
		if err != nil {
			t.Fatalf("RegisterClient: %v", err)
		}
		if revision != 1 {
			t.Fatalf("RegisterClient revision = %d, want 1", revision)
		}
		want := newClientRegistration("client-a")
		want.Revision = 1
		assertRegistration(t, mustFindRegistration(t, store, "client-a"), want)
		client, err := store.FindClientById(context.Background(), "client-a")
		if err != nil {
			t.Fatalf("FindClientById: %v", err)
		}
		assertClient(t, client, want.Client)
	})
	mustCase(t, "DuplicateRegistrationRejected", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		mustRegister(t, store, newClientRegistration("client-a"))
		duplicate := newClientRegistration("client-a")
		duplicate.Client.ClientName = "impostor"
		duplicate.RegistrationAccessTokenDigest = "digest-impostor"
		if _, err := store.RegisterClient(context.Background(), duplicate); !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("duplicate RegisterClient error = %v, want ErrDuplicateHandle", err)
		}
		want := newClientRegistration("client-a")
		want.Revision = 1
		assertRegistration(t, mustFindRegistration(t, store, "client-a"), want)
	})
	mustCase(t, "ConcurrentRegistrationSucceedsOnce", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		errs := raceClientRegistration(func(i int) error {
			registration := newClientRegistration("client-a")
			registration.RegistrationAccessTokenDigest = "digest-" + string(rune('a'+i))
			_, err := store.RegisterClient(context.Background(), registration)
			return err
		})
		assertExactlyOneSuccess(t, errs, storage.ErrDuplicateHandle)
		if got := mustFindRegistration(t, store, "client-a"); got.Revision != 1 {
			t.Fatalf("revision after concurrent registration = %d, want 1", got.Revision)
		}
	})
	mustCase(t, "UpdateWithExpectedRevision", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		mustRegister(t, store, newClientRegistration("client-a"))
		for expected := 1; expected <= 2; expected++ {
			updated := updatedClientRegistration("client-a", expected)
			updated.Revision = 99
			revision, err := store.UpdateClientRegistration(context.Background(), updated, expected)
			if err != nil {
				t.Fatalf("UpdateClientRegistration(expected %d): %v", expected, err)
			}
			if revision != expected+1 {
				t.Fatalf("UpdateClientRegistration(expected %d) revision = %d, want %d", expected, revision, expected+1)
			}
			want := updatedClientRegistration("client-a", expected)
			want.Revision = expected + 1
			assertRegistration(t, mustFindRegistration(t, store, "client-a"), want)
			client, err := store.FindClientById(context.Background(), "client-a")
			if err != nil {
				t.Fatalf("FindClientById after update: %v", err)
			}
			assertClient(t, client, want.Client)
		}
	})
	mustCase(t, "VersionConflictKeepsRecord", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		mustRegister(t, store, newClientRegistration("client-a"))
		if _, err := store.UpdateClientRegistration(context.Background(), updatedClientRegistration("client-a", 1), 1); err != nil {
			t.Fatalf("UpdateClientRegistration: %v", err)
		}
		want := updatedClientRegistration("client-a", 1)
		want.Revision = 2
		for _, stale := range []int{1, 3} {
			if _, err := store.UpdateClientRegistration(context.Background(), updatedClientRegistration("client-a", 7), stale); !errors.Is(err, storage.ErrVersionConflict) {
				t.Fatalf("update with revision %d error = %v, want ErrVersionConflict", stale, err)
			}
			assertRegistration(t, mustFindRegistration(t, store, "client-a"), want)
			if err := store.RemoveClientRegistration(context.Background(), "client-a", stale); !errors.Is(err, storage.ErrVersionConflict) {
				t.Fatalf("remove with revision %d error = %v, want ErrVersionConflict", stale, err)
			}
			assertRegistration(t, mustFindRegistration(t, store, "client-a"), want)
		}
	})
	mustCase(t, "ConflictRetryAfterReload", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		mustRegister(t, store, newClientRegistration("client-a"))
		readByA := mustFindRegistration(t, store, "client-a")
		readByB := mustFindRegistration(t, store, "client-a")

		if revision, err := store.UpdateClientRegistration(context.Background(), updatedClientRegistration("client-a", 1), readByA.Revision); err != nil || revision != 2 {
			t.Fatalf("update by A = %d, %v; want 2, nil", revision, err)
		}
		fromB := updatedClientRegistration("client-a", 2)
		if _, err := store.UpdateClientRegistration(context.Background(), fromB, readByB.Revision); !errors.Is(err, storage.ErrVersionConflict) {
			t.Fatalf("stale update by B error = %v, want ErrVersionConflict", err)
		}
		reloaded := mustFindRegistration(t, store, "client-a")
		if reloaded.Revision != 2 {
			t.Fatalf("reloaded revision = %d, want 2", reloaded.Revision)
		}
		revision, err := store.UpdateClientRegistration(context.Background(), fromB, reloaded.Revision)
		if err != nil || revision != 3 {
			t.Fatalf("retried update by B = %d, %v; want 3, nil", revision, err)
		}
		want := updatedClientRegistration("client-a", 2)
		want.Revision = 3
		assertRegistration(t, mustFindRegistration(t, store, "client-a"), want)
	})
	mustCase(t, "ConcurrentUpdateSucceedsOnce", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		mustRegister(t, store, newClientRegistration("client-a"))
		errs := raceClientRegistration(func(i int) error {
			_, err := store.UpdateClientRegistration(context.Background(), updatedClientRegistration("client-a", i+1), 1)
			return err
		})
		assertExactlyOneSuccess(t, errs, storage.ErrVersionConflict)
		if got := mustFindRegistration(t, store, "client-a"); got.Revision != 2 {
			t.Fatalf("revision after concurrent update = %d, want 2", got.Revision)
		}
	})
	mustCase(t, "UpdateAndRemoveMissingReturnSentinel", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		_, err := store.UpdateClientRegistration(context.Background(), newClientRegistration("missing"), 1)
		expectNotFound(t, err)
		expectNotFound(t, store.RemoveClientRegistration(context.Background(), "missing", 1))
	})
	mustCase(t, "RemoveMakesRecordUnreadable", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		mustRegister(t, store, newClientRegistration("client-a"))
		mustRegister(t, store, newClientRegistration("client-b"))
		if err := store.RemoveClientRegistration(context.Background(), "client-a", 1); err != nil {
			t.Fatalf("RemoveClientRegistration: %v", err)
		}
		_, err := store.FindClientRegistration(context.Background(), "client-a")
		expectNotFound(t, err)
		_, err = store.FindClientById(context.Background(), "client-a")
		expectNotFound(t, err)
		if _, err := store.FindClientById(context.Background(), "client-b"); err != nil {
			t.Fatalf("unrelated client removed: %v", err)
		}
	})
	// A removed client id stays taken: a later registration under it must not
	// revive the removed client for the credentials it issued.
	mustCase(t, "TombstoneBlocksReRegistration", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		mustRegister(t, store, newClientRegistration("client-a"))
		if err := store.RemoveClientRegistration(context.Background(), "client-a", 1); err != nil {
			t.Fatalf("RemoveClientRegistration: %v", err)
		}
		if _, err := store.RegisterClient(context.Background(), newClientRegistration("client-a")); !errors.Is(err, storage.ErrDuplicateHandle) {
			t.Fatalf("re-registration of a removed client id error = %v, want ErrDuplicateHandle", err)
		}
		_, err := store.FindClientRegistration(context.Background(), "client-a")
		expectNotFound(t, err)
		_, err = store.FindClientById(context.Background(), "client-a")
		expectNotFound(t, err)
		_, err = store.UpdateClientRegistration(context.Background(), newClientRegistration("client-a"), 1)
		expectNotFound(t, err)
		expectNotFound(t, store.RemoveClientRegistration(context.Background(), "client-a", 1))
	})
	mustCase(t, "OriginLookupMatchesExactly", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		lookup, ok := store.(storage.ClientOriginLookup)
		if !ok {
			t.Fatalf("store %T does not implement storage.ClientOriginLookup", store)
		}
		withOrigins := func(id string, enabled bool, origins ...string) *models.ClientRegistration {
			registration := newClientRegistration(id)
			registration.Client.Enabled = enabled
			registration.Client.AllowedCorsOrigins = origins
			return registration
		}
		mustRegister(t, store, withOrigins("match", true, "https://a.example", "https://b.example"))
		mustRegister(t, store, withOrigins("disabled-match", false, "https://a.example"))
		mustRegister(t, store, withOrigins("near-miss", true, "https://a.example:8443", "https://A.example", "https://a.example/"))
		mustRegister(t, store, withOrigins("removed", true, "https://a.example"))
		if err := store.RemoveClientRegistration(context.Background(), "removed", 1); err != nil {
			t.Fatalf("RemoveClientRegistration: %v", err)
		}

		got, err := lookup.FindClientsByAllowedOrigin(context.Background(), "https://a.example")
		if err != nil {
			t.Fatalf("FindClientsByAllowedOrigin: %v", err)
		}
		ids := make([]string, 0, len(got))
		for _, client := range got {
			ids = append(ids, client.ClientId)
		}
		slices.Sort(ids)
		if want := []string{"disabled-match", "match"}; !slices.Equal(ids, want) {
			t.Fatalf("FindClientsByAllowedOrigin ids = %v, want %v", ids, want)
		}

		miss, err := lookup.FindClientsByAllowedOrigin(context.Background(), "https://unknown.example")
		if err != nil {
			t.Fatalf("FindClientsByAllowedOrigin(miss): %v", err)
		}
		expectEmptySlice(t, miss)

		// An update replacing the origins is what later lookups see.
		moved := withOrigins("match", true, "https://moved.example")
		if _, err := store.UpdateClientRegistration(context.Background(), moved, 1); err != nil {
			t.Fatalf("UpdateClientRegistration: %v", err)
		}
		lookupIds := func(origin string) []string {
			t.Helper()
			clients, err := lookup.FindClientsByAllowedOrigin(context.Background(), origin)
			if err != nil {
				t.Fatalf("FindClientsByAllowedOrigin(%s): %v", origin, err)
			}
			ids := make([]string, 0, len(clients))
			for _, client := range clients {
				ids = append(ids, client.ClientId)
			}
			slices.Sort(ids)
			return ids
		}
		if got, want := lookupIds("https://a.example"), []string{"disabled-match"}; !slices.Equal(got, want) {
			t.Fatalf("after update, old origin ids = %v, want %v", got, want)
		}
		if got, want := lookupIds("https://moved.example"), []string{"match"}; !slices.Equal(got, want) {
			t.Fatalf("after update, new origin ids = %v, want %v", got, want)
		}
	})
	cfg.mayCase(t, "ReturnedRecordIsolated", func(t *testing.T) {
		t.Parallel()
		store := newStore()
		input := newClientRegistration("client-a")
		mustRegister(t, store, input)
		input.Client.ClientName = "changed after register"
		input.Client.RedirectUris[0] = "https://changed.example/cb"

		got := mustFindRegistration(t, store, "client-a")
		got.Client.ClientName = "changed after read"
		got.Client.AllowedScopes[0] = "changed"
		got.Client.Properties["tier"] = "changed"
		got.RegistrationAccessTokenDigest = "changed"
		got.Revision = 77
		client, err := store.FindClientById(context.Background(), "client-a")
		if err != nil {
			t.Fatalf("FindClientById: %v", err)
		}
		client.ClientSecrets[0].Value = "changed"

		want := newClientRegistration("client-a")
		want.Revision = 1
		assertRegistration(t, mustFindRegistration(t, store, "client-a"), want)
	})
	mustCase(t, "NoBackgroundGoroutines", func(t *testing.T) {
		runNoBackgroundGoroutinesCase(t, newStore, func(store storage.ClientRegistrationStore) {
			_, _ = store.RegisterClient(context.Background(), newClientRegistration("client-a"))
			_, _ = store.FindClientRegistration(context.Background(), "client-a")
			_, _ = store.FindClientById(context.Background(), "client-a")
			_, _ = store.UpdateClientRegistration(context.Background(), updatedClientRegistration("client-a", 1), 1)
			if lookup, ok := store.(storage.ClientOriginLookup); ok {
				_, _ = lookup.FindClientsByAllowedOrigin(context.Background(), "https://a.example")
			}
			_ = store.RemoveClientRegistration(context.Background(), "client-a", 2)
		})
	})
	cfg.maybeAssertConformsTo(t, "ConformsToCredential", newStore())
}

// newClientRegistration builds a deterministic registration with the client
// fields a round trip has to keep, the allowed grant types among them.
func newClientRegistration(clientId string) *models.ClientRegistration {
	client := models.NewClient()
	client.ClientId = clientId
	client.ClientName = "Client " + clientId
	client.ClientSecrets = []*models.Secret{{Description: "primary", Value: "hashed-secret", Expiration: fixedAlive, Type: wicket.SecretTypesSharedSecret}}
	client.RedirectUris = []string{"https://" + clientId + ".example/cb"}
	client.AllowedScopes = []string{"openid", "profile"}
	client.AllowedCorsOrigins = []string{"https://" + clientId + ".example"}
	client.Claims = []*models.ClientClaim{{Type: "role", Value: "reader", ValueType: "string"}}
	client.Properties = map[string]string{"tier": "basic"}
	lifetime := 600
	client.ConsentLifetime = &lifetime
	client.TokenEndpointAuthMethod = "private_key_jwt"
	client.JwksUri = "https://" + clientId + ".example/jwks"
	client.TokenEndpointAuthSigningAlgorithms = []string{"RS256"}
	if err := client.SetAllowedGrantTypes([]string{wicket.GrantTypeAuthorizationCode, wicket.GrantTypeClientCredentials}); err != nil {
		panic(err)
	}
	return &models.ClientRegistration{
		Client:                        client,
		RegistrationAccessTokenDigest: "digest-" + clientId,
		RegistrationTime:              fixedNow,
	}
}

// updatedClientRegistration is the registration of clientId as changed by
// update number n: its name, grant types and token digest differ from the
// registered one and from every other update.
func updatedClientRegistration(clientId string, n int) *models.ClientRegistration {
	registration := newClientRegistration(clientId)
	suffix := string(rune('a' + n%26))
	registration.Client.ClientName = "Updated " + clientId + " " + suffix
	registration.Client.AllowedScopes = []string{"openid", "scope-" + suffix}
	registration.RegistrationAccessTokenDigest = "digest-" + clientId + "-" + suffix
	if err := registration.Client.SetAllowedGrantTypes([]string{wicket.GrantTypeClientCredentials}); err != nil {
		panic(err)
	}
	return registration
}

func mustRegister(t *testing.T, store storage.ClientRegistrationStore, registration *models.ClientRegistration) {
	t.Helper()
	revision, err := store.RegisterClient(context.Background(), registration)
	if err != nil {
		t.Fatalf("RegisterClient(%s): %v", registration.Client.ClientId, err)
	}
	if revision != 1 {
		t.Fatalf("RegisterClient(%s) revision = %d, want 1", registration.Client.ClientId, revision)
	}
}

func mustFindRegistration(t *testing.T, store storage.ClientRegistrationStore, clientId string) *models.ClientRegistration {
	t.Helper()
	registration, err := store.FindClientRegistration(context.Background(), clientId)
	if err != nil {
		t.Fatalf("FindClientRegistration(%s): %v", clientId, err)
	}
	if registration == nil || registration.Client == nil {
		t.Fatalf("FindClientRegistration(%s) = %v, want a record with a client", clientId, registration)
	}
	return registration
}

func assertRegistration(t *testing.T, got, want *models.ClientRegistration) {
	t.Helper()
	if got.Revision != want.Revision {
		t.Fatalf("Revision = %d, want %d", got.Revision, want.Revision)
	}
	if got.RegistrationAccessTokenDigest != want.RegistrationAccessTokenDigest {
		t.Fatalf("RegistrationAccessTokenDigest = %q, want %q", got.RegistrationAccessTokenDigest, want.RegistrationAccessTokenDigest)
	}
	if !got.RegistrationTime.Equal(want.RegistrationTime) {
		t.Fatalf("RegistrationTime = %v, want %v", got.RegistrationTime, want.RegistrationTime)
	}
	assertClient(t, got.Client, want.Client)
}

func assertClient(t *testing.T, got, want *models.Client) {
	t.Helper()
	if got == nil {
		t.Fatal("client is nil")
	}
	if !slices.Equal(got.AllowedGrantTypes(), want.AllowedGrantTypes()) {
		t.Fatalf("AllowedGrantTypes = %v, want %v", got.AllowedGrantTypes(), want.AllowedGrantTypes())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("client mismatch:\n got %#v\nwant %#v", got, want)
	}
}

// raceClientRegistration runs op from clientRegistrationConcurrency goroutines
// released together and returns their errors.
func raceClientRegistration(op func(i int) error) []error {
	errs := make([]error, clientRegistrationConcurrency)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range clientRegistrationConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = op(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

func assertExactlyOneSuccess(t *testing.T, errs []error, loser error) {
	t.Helper()
	successes := 0
	for _, err := range errs {
		switch {
		case err == nil:
			successes++
		case !errors.Is(err, loser):
			t.Fatalf("racing write error = %v, want nil or %v", err, loser)
		}
	}
	if successes != 1 {
		t.Fatalf("%d racing writes succeeded, want exactly 1", successes)
	}
}
