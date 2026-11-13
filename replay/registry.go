// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replay

import (
	"context"
	"errors"
	"time"
)

// ErrDuplicateHandle reports that the key offered to Register is already
// registered and has not been reclaimed. Callers treat it as a replay.
// Adapters may wrap it; callers match it with errors.Is.
var ErrDuplicateHandle = errors.New("replay: duplicate handle")

// ErrInvalidArgument reports that Register was given an empty key or a zero
// expiry instant. It is never a replay verdict: callers treat it like any
// other infrastructure failure.
var ErrInvalidArgument = errors.New("replay: invalid argument")

// Registry records one-time keys. Both methods are safe for concurrent use,
// take the caller's context without replacing or bounding it, and never
// consult a clock.
type Registry interface {
	// Register records key with the instant its record may be reclaimed.
	//
	// It returns nil when the key is not registered (never was, or was
	// reclaimed). When the key is registered it returns an error matching
	// ErrDuplicateHandle and leaves the stored record, including its expiry
	// instant, exactly as it was — whether or not that instant has passed.
	// Concurrent calls for one key yield exactly one nil; every other call
	// yields ErrDuplicateHandle and nothing else.
	//
	// An empty key or a zero expiresAt yields an error matching
	// ErrInvalidArgument and records nothing. An expiresAt in the past is
	// recorded like any other.
	//
	// Keys come from Key: 64 characters out of [0-9a-f], compared byte for
	// byte. A medium coarser than a nanosecond stores expiresAt rounded
	// later, never earlier.
	//
	// With a cancelled context a call may complete normally or return an
	// error matching context.Canceled; it must not report ErrDuplicateHandle
	// for a key that was not registered, nor nil for one that was.
	Register(ctx context.Context, key string, expiresAt time.Time) error

	// RemoveExpired drops every record whose expiry instant is strictly
	// before cutoff and returns how many this call dropped. A record expiring
	// exactly at cutoff stays. Instants are compared as instants, whatever
	// their location. A dropped key can be registered again.
	//
	// This is the only way records leave a registry: no reclaiming inside
	// Register, no native expiry or eviction of the medium, no background
	// work. On failure the count says how many records were dropped before
	// the error; callers must not rely on it. A cancelled context never
	// causes an unexpired record to be dropped.
	RemoveExpired(ctx context.Context, cutoff time.Time) (int, error)
}
