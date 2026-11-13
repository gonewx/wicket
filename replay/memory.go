// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replay

import (
	"context"
	"sync"
	"time"
)

// MemoryRegistry is a Registry kept in process memory. It is correct within
// one process only: replicas each hold their own records, so it does not
// protect a deployment with more than one replica.
//
// It holds no resources, starts nothing in the background and never reads a
// clock; records leave only through RemoveExpired.
//
// A call made with a context that is already done changes nothing and
// returns the context's error; Register reports an empty key or a zero
// expiry first. The zero value is an empty registry ready for use.
type MemoryRegistry struct {
	mu      sync.Mutex
	records map[string]time.Time
}

var _ Registry = (*MemoryRegistry)(nil)

// NewMemoryRegistry returns an empty registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{records: map[string]time.Time{}}
}

// Register implements Registry.
func (r *MemoryRegistry) Register(ctx context.Context, key string, expiresAt time.Time) error {
	if key == "" || expiresAt.IsZero() {
		return ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, registered := r.records[key]; registered {
		return ErrDuplicateHandle
	}
	if r.records == nil {
		r.records = map[string]time.Time{}
	}
	// Round(0) drops the monotonic reading so later comparisons are between
	// instants only.
	r.records[key] = expiresAt.Round(0)
	return nil
}

// RemoveExpired implements Registry.
func (r *MemoryRegistry) RemoveExpired(ctx context.Context, cutoff time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	cutoff = cutoff.Round(0)

	r.mu.Lock()
	defer r.mu.Unlock()
	removed := 0
	for key, expiresAt := range r.records {
		if expiresAt.Before(cutoff) {
			delete(r.records, key)
			removed++
		}
	}
	return removed, nil
}
