// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dynamicscheme

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func provider(scheme string, enabled bool) *Provider {
	return &Provider{
		Scheme:      scheme,
		DisplayName: scheme + " display",
		Enabled:     enabled,
		Protocol:    "oidc",
		Config:      map[string]string{"authority": "https://" + scheme + ".example"},
	}
}

func TestProviderCloneIsolatesConfig(t *testing.T) {
	t.Parallel()

	original := provider("a", true)
	dup := original.clone()
	dup.Config["authority"] = "mutated"
	if original.Config["authority"] == "mutated" {
		t.Fatal("clone shares the Config map with the original")
	}
	if dup.Scheme != original.Scheme || dup.Protocol != original.Protocol {
		t.Fatal("clone lost scalar fields")
	}
	if (*Provider)(nil).clone() != nil {
		t.Fatal("nil clone should be nil")
	}
}

func TestMemoryStoreCopiesOnWriteAndRead(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	in := provider("a", true)
	if err := store.PutProvider(in); err != nil {
		t.Fatalf("PutProvider: %v", err)
	}
	// Mutating the input after Put must not affect stored state.
	in.Config["authority"] = "mutated-input"

	got, err := store.GetProvider("a")
	if err != nil || got == nil {
		t.Fatalf("GetProvider: got=%v err=%v", got, err)
	}
	if got.Config["authority"] != "https://a.example" {
		t.Fatalf("stored record reflects post-Put input mutation: %q", got.Config["authority"])
	}
	// Mutating the returned copy must not affect stored state.
	got.Config["authority"] = "mutated-output"
	again, _ := store.GetProvider("a")
	if again.Config["authority"] != "https://a.example" {
		t.Fatalf("stored record reflects post-Get output mutation: %q", again.Config["authority"])
	}
}

func TestMemoryStoreLifecycle(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, s *MemoryStore){
		"get absent returns nil": func(t *testing.T, s *MemoryStore) {
			got, err := s.GetProvider("missing")
			if err != nil || got != nil {
				t.Fatalf("got=%v err=%v, want nil,nil", got, err)
			}
		},
		"put empty scheme rejected": func(t *testing.T, s *MemoryStore) {
			if err := s.PutProvider(&Provider{Scheme: ""}); err == nil {
				t.Fatal("empty scheme should be rejected")
			}
		},
		"put nil rejected": func(t *testing.T, s *MemoryStore) {
			if err := s.PutProvider(nil); err == nil {
				t.Fatal("nil provider should be rejected")
			}
		},
		"upsert replaces": func(t *testing.T, s *MemoryStore) {
			_ = s.PutProvider(provider("a", true))
			replacement := provider("a", false)
			replacement.DisplayName = "replaced"
			_ = s.PutProvider(replacement)
			got, _ := s.GetProvider("a")
			if got.DisplayName != "replaced" || got.Enabled {
				t.Fatalf("upsert did not replace: %+v", got)
			}
		},
		"delete absent is no-op": func(t *testing.T, s *MemoryStore) {
			if err := s.DeleteProvider("missing"); err != nil {
				t.Fatalf("delete absent: %v", err)
			}
		},
		"delete removes": func(t *testing.T, s *MemoryStore) {
			_ = s.PutProvider(provider("a", true))
			_ = s.DeleteProvider("a")
			got, _ := s.GetProvider("a")
			if got != nil {
				t.Fatal("delete did not remove")
			}
		},
		"all is ordered": func(t *testing.T, s *MemoryStore) {
			_ = s.PutProvider(provider("c", true))
			_ = s.PutProvider(provider("a", true))
			_ = s.PutProvider(provider("b", false))
			all, err := s.AllProviders()
			if err != nil {
				t.Fatalf("AllProviders: %v", err)
			}
			if len(all) != 3 || all[0].Scheme != "a" || all[1].Scheme != "b" || all[2].Scheme != "c" {
				t.Fatalf("AllProviders not sorted: %v", schemes(all))
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			run(t, NewMemoryStore())
		})
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scheme := fmt.Sprintf("s%d", i%10)
			_ = store.PutProvider(provider(scheme, true))
			_, _ = store.GetProvider(scheme)
			_, _ = store.AllProviders()
			if i%3 == 0 {
				_ = store.DeleteProvider(scheme)
			}
		}(i)
	}
	wg.Wait()
}

func TestResolverDisabled(t *testing.T) {
	t.Parallel()

	r := NewResolver(NewMemoryStore(), newFakeClock(), false, time.Minute)
	if r.Enabled() {
		t.Fatal("resolver should report disabled")
	}
	if _, ok, err := r.Get("a"); ok || err != nil {
		t.Fatalf("disabled Get = ok:%v err:%v, want false,nil", ok, err)
	}
	if all, err := r.All(); all != nil || err != nil {
		t.Fatalf("disabled All = %v,%v, want nil,nil", all, err)
	}
	if err := r.Register(provider("a", true)); err == nil {
		t.Fatal("disabled Register should error")
	}
	if err := r.Remove("a"); err == nil {
		t.Fatal("disabled Remove should error")
	}
}

func TestResolverEnabledResolution(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	_ = store.PutProvider(provider("live", true))
	_ = store.PutProvider(provider("off", false))
	r := NewResolver(store, newFakeClock(), true, time.Minute)

	if _, ok, err := r.Get("live"); !ok || err != nil {
		t.Fatalf("Get live = ok:%v err:%v, want true,nil", ok, err)
	}
	if _, ok, _ := r.Get("off"); ok {
		t.Fatal("individually-disabled provider should not resolve")
	}
	if _, ok, _ := r.Get("missing"); ok {
		t.Fatal("missing provider should not resolve")
	}
	all, err := r.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	if len(all) != 1 || all[0].Scheme != "live" {
		t.Fatalf("All = %v, want [live]", schemes(all))
	}
	// Store still exposes the disabled row for a management surface.
	stored, _ := store.AllProviders()
	if len(stored) != 2 {
		t.Fatalf("store AllProviders = %d, want 2 (including disabled)", len(stored))
	}
}

func TestResolverRegisterRemove(t *testing.T) {
	t.Parallel()

	r := NewResolver(NewMemoryStore(), newFakeClock(), true, time.Minute)
	if err := r.Register(provider("a", true)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, ok, _ := r.Get("a"); !ok {
		t.Fatal("registered provider should resolve immediately (cache invalidated)")
	}
	if err := r.Remove("a"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok, _ := r.Get("a"); ok {
		t.Fatal("removed provider should not resolve immediately")
	}
}

func TestResolverCacheTTL(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	_ = store.PutProvider(provider("a", true))
	clock := newFakeClock()
	r := NewResolver(store, clock, true, time.Minute)

	// Prime the cache.
	if _, ok, _ := r.Get("a"); !ok {
		t.Fatal("expected a to resolve")
	}
	// A direct store write (bypassing Register) is not seen within the TTL.
	_ = store.PutProvider(provider("b", true))
	if _, ok, _ := r.Get("b"); ok {
		t.Fatal("store change should not be visible within TTL")
	}
	// After the TTL elapses the reload sees it.
	clock.advance(2 * time.Minute)
	if _, ok, _ := r.Get("b"); !ok {
		t.Fatal("store change should be visible after TTL")
	}
}

func TestResolverCacheDisabled(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	clock := newFakeClock()
	r := NewResolver(store, clock, true, 0) // caching disabled

	_ = store.PutProvider(provider("a", true))
	if _, ok, _ := r.Get("a"); !ok {
		t.Fatal("with caching disabled a direct store write is seen immediately")
	}
}

func TestResolverConcurrent(t *testing.T) {
	t.Parallel()

	r := NewResolver(NewMemoryStore(), newFakeClock(), true, time.Millisecond)
	var wg sync.WaitGroup
	var errs atomic.Int64
	for i := range 50 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			scheme := fmt.Sprintf("s%d", i%10)
			if err := r.Register(provider(scheme, true)); err != nil {
				errs.Add(1)
			}
			_, _, _ = r.Get(scheme)
			_, _ = r.All()
			if i%3 == 0 {
				_ = r.Remove(scheme)
			}
		}(i)
	}
	wg.Wait()
	if errs.Load() != 0 {
		t.Fatalf("unexpected register errors: %d", errs.Load())
	}
}

func schemes(providers []*Provider) []string {
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.Scheme)
	}
	return out
}

// scriptedStore is a ProviderStore whose AllProviders output is fully
// controlled, used to exercise resolver robustness against store types that
// violate the store contract (duplicate keys, unsorted, empty scheme).
type scriptedStore struct{ all []*Provider }

func (s scriptedStore) GetProvider(string) (*Provider, error) { return nil, nil }
func (s scriptedStore) AllProviders() ([]*Provider, error)    { return s.all, nil }
func (s scriptedStore) PutProvider(*Provider) error           { return nil }
func (s scriptedStore) DeleteProvider(string) error           { return nil }

func TestNewResolverNilSeamGuards(t *testing.T) {
	t.Parallel()

	// A nil store must not panic on the enabled path; it falls back to an empty
	// in-memory store.
	rStore := NewResolver(nil, newFakeClock(), true, time.Minute)
	if _, ok, err := rStore.Get("a"); ok || err != nil {
		t.Fatalf("nil-store Get = ok:%v err:%v, want false,nil", ok, err)
	}
	if all, err := rStore.All(); len(all) != 0 || err != nil {
		t.Fatalf("nil-store All = %v,%v, want empty,nil", all, err)
	}
	if err := rStore.Register(provider("a", true)); err != nil {
		t.Fatalf("nil-store Register into fallback store: %v", err)
	}

	// A nil clock with a positive TTL must not panic: caching is disabled so the
	// clock is never read.
	rClock := NewResolver(NewMemoryStore(), nil, true, time.Minute)
	_ = rClock.Register(provider("a", true))
	if _, ok, err := rClock.Get("a"); !ok || err != nil {
		t.Fatalf("nil-clock Get = ok:%v err:%v, want true,nil", ok, err)
	}
}

func TestResolverSnapshotRobustAgainstMisbehavingStore(t *testing.T) {
	t.Parallel()

	// Store returns duplicate schemes, unsorted order, an empty-scheme row, a nil
	// entry, and a disabled row — all of which the resolver must normalize.
	store := scriptedStore{all: []*Provider{
		provider("c", true),
		provider("a", true),
		provider("a", true),  // duplicate key
		provider("", true),   // empty scheme
		nil,                  // nil entry
		provider("b", false), // individually disabled
	}}
	r := NewResolver(store, newFakeClock(), true, 0) // caching off: reload every read

	all, err := r.All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	// Deduplicated (a once), empty scheme filtered, disabled filtered, sorted.
	if got := schemes(all); len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("All = %v, want [a c] (deduped, empty-filtered, sorted)", got)
	}
	// Get must be self-consistent with All: empty scheme absent, present ones hit.
	if _, ok, _ := r.Get(""); ok {
		t.Fatal("empty-scheme record must not resolve")
	}
	if _, ok, _ := r.Get("a"); !ok {
		t.Fatal("scheme a should resolve")
	}
	if _, ok, _ := r.Get("b"); ok {
		t.Fatal("disabled scheme b must not resolve")
	}
}
