// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dynamicscheme

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// snapshot is an immutable enabled-provider view: a lookup map plus a
// scheme-ordered slice. Once built it is never mutated, so it can be shared
// across goroutines without further locking.
type snapshot struct {
	byScheme map[string]*Provider
	ordered  []*Provider
}

// Resolver merges the dynamic provider store view behind a per-instance TTL
// cache. When disabled it exposes no dynamic providers and refuses registration,
// preserving the static-only pass-through baseline. The cache holds the
// enabled-provider snapshot with an absolute expiry computed from the injected
// clock; a read after expiry reloads from the store, and Register/Remove
// invalidate the cache immediately so a runtime change is visible without waiting
// for the TTL. A non-positive cacheTTL disables caching.
type Resolver struct {
	store    ProviderStore
	clock    Clock
	enabled  bool
	cacheTTL time.Duration

	mu        sync.Mutex
	cached    *snapshot
	expiresAt time.Time
}

// NewResolver builds a resolver over store and clock. When enabled is false the
// resolver behaves as an empty dynamic source. A nil store falls back to an
// in-memory store; a nil clock disables caching (caching needs a time source),
// so the enabled path never dereferences a nil seam. The DI path always injects
// both, so these guards only matter for direct construction.
func NewResolver(store ProviderStore, clock Clock, enabled bool, cacheTTL time.Duration) *Resolver {
	if store == nil {
		store = NewMemoryStore()
	}
	if clock == nil {
		cacheTTL = 0
	}
	return &Resolver{store: store, clock: clock, enabled: enabled, cacheTTL: cacheTTL}
}

// Enabled reports whether the dynamic subsystem is active.
func (r *Resolver) Enabled() bool { return r != nil && r.enabled }

// Get returns the enabled provider for scheme. A disabled resolver, a missing
// scheme, or an individually-disabled provider all return (nil, false, nil).
func (r *Resolver) Get(scheme string) (*Provider, bool, error) {
	if !r.Enabled() {
		return nil, false, nil
	}
	snap, err := r.snapshot()
	if err != nil {
		return nil, false, err
	}
	provider, ok := snap.byScheme[scheme]
	if !ok {
		return nil, false, nil
	}
	return provider.clone(), true, nil
}

// All returns every enabled provider ordered by scheme name. A disabled resolver
// returns (nil, nil).
func (r *Resolver) All() ([]*Provider, error) {
	if !r.Enabled() {
		return nil, nil
	}
	snap, err := r.snapshot()
	if err != nil {
		return nil, err
	}
	out := make([]*Provider, 0, len(snap.ordered))
	for _, provider := range snap.ordered {
		out = append(out, provider.clone())
	}
	return out, nil
}

// Register upserts a provider and invalidates the cache. It errors when the
// resolver is disabled.
func (r *Resolver) Register(provider *Provider) error {
	if !r.Enabled() {
		return fmt.Errorf("dynamic provider subsystem is disabled")
	}
	if err := r.store.PutProvider(provider); err != nil {
		return err
	}
	r.invalidate()
	return nil
}

// Remove deletes a provider by scheme and invalidates the cache. It errors when
// the resolver is disabled.
func (r *Resolver) Remove(scheme string) error {
	if !r.Enabled() {
		return fmt.Errorf("dynamic provider subsystem is disabled")
	}
	if err := r.store.DeleteProvider(scheme); err != nil {
		return err
	}
	r.invalidate()
	return nil
}

// snapshot returns the current enabled-provider snapshot, reloading from the
// store when the cache is empty, expired, or caching is disabled.
func (r *Resolver) snapshot() (*snapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cacheTTL > 0 && r.cached != nil && !r.expired() {
		return r.cached, nil
	}

	providers, err := r.store.AllProviders()
	if err != nil {
		return nil, err
	}

	// Build byScheme first, then derive ordered from it so the two views stay
	// consistent (deduplicated, empty-scheme-filtered, scheme-ordered) even when
	// a store implementation returns duplicate or unsorted records.
	snap := &snapshot{byScheme: make(map[string]*Provider, len(providers))}
	for _, provider := range providers {
		if provider == nil || !provider.Enabled || provider.Scheme == "" {
			continue
		}
		snap.byScheme[provider.Scheme] = provider
	}
	ordered := make([]string, 0, len(snap.byScheme))
	for scheme := range snap.byScheme {
		ordered = append(ordered, scheme)
	}
	sort.Strings(ordered)
	snap.ordered = make([]*Provider, 0, len(ordered))
	for _, scheme := range ordered {
		snap.ordered = append(snap.ordered, snap.byScheme[scheme])
	}

	if r.cacheTTL > 0 {
		r.cached = snap
		r.expiresAt = r.clock.Now().Add(r.cacheTTL)
	} else {
		r.cached = nil
		r.expiresAt = time.Time{}
	}
	return snap, nil
}

// expired reports whether the cached snapshot has passed its absolute expiry.
func (r *Resolver) expired() bool {
	return !r.expiresAt.IsZero() && !r.clock.Now().Before(r.expiresAt)
}

// invalidate drops the cached snapshot so the next read reloads from the store.
func (r *Resolver) invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cached = nil
	r.expiresAt = time.Time{}
}
