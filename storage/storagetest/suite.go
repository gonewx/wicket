// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storagetest

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/gonewx/wicket/storage"
)

// SuiteVersion identifies the contract version this suite verifies. A
// compliant adapter exposes ConformsTo() string returning this value; a host
// compares adapter.ConformsTo() to SuiteVersion at assembly time.
const SuiteVersion = "1.0.0"

// Option configures a suite run.
type Option func(*options)

type options struct {
	may bool
}

// WithMay enables MAY-graded cases. MAY cases are skipped by default so an
// adapter can claim compliance on the MUST surface alone; enabling them runs
// the enhanced cases as well.
func WithMay(enabled bool) Option {
	return func(o *options) { o.may = enabled }
}

func newOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// mustCase registers a MUST-graded case. MUST cases always run and never skip.
func mustCase(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run("MUST/"+name, fn)
}

// mayCase registers a MAY-graded case, skipped unless WithMay(true) is set.
func (o options) mayCase(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run("MAY/"+name, func(t *testing.T) {
		if !o.may {
			t.Skip("MAY case skipped; pass storagetest.WithMay(true)")
		}
		fn(t)
	})
}

// Fixed time basis for expiry-semantics cases. The suite never consults the
// real clock, so every run is deterministic regardless of when it executes.
var (
	fixedNow     = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fixedExpired = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	fixedAlive   = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
)

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expectNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("error = %v, want storage.ErrNotFound", err)
	}
}

func expectEmptySlice[T any](t *testing.T, got []T) {
	t.Helper()
	if got == nil {
		t.Fatal("result is nil, want empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("len = %d, want 0", len(got))
	}
}

// assertCancellationReadMiss checks that a read under a cancelled context
// still surfaces an error instead of fabricating a result or swallowing the
// miss. The sentinel and the cancellation error are both acceptable; a nil
// error is not.
func assertCancellationReadMiss(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("read with cancelled context returned nil error and nil record")
	}
}

// assertCancellationWrite checks the two acceptable outcomes of a write under
// a cancelled context: the cancellation propagates as an error, or the
// adapter legitimately completes (in-memory adapters have no I/O to cancel)
// and the write is then observable. A nil error with no observable effect is
// a swallowed cancellation and fails.
func assertCancellationWrite(t *testing.T, err error, observe func() error) {
	t.Helper()
	if err == nil {
		if obsErr := observe(); obsErr != nil {
			t.Fatalf("write reported success but the record is not observable: %v", obsErr)
		}
		return
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("write with cancelled context returned %v, want context.Canceled", err)
	}
}

// conformanceCredential is the optional adapter credential declared in the
// package documentation.
type conformanceCredential interface {
	ConformsTo() string
}

// goroutineSettleSamples and goroutineSettleInterval fix the settle window
// for the no-background-activity case: the minimum over 10 samples at 5ms
// spacing. goroutineTolerance absorbs unrelated test-framework parallelism
// that can legitimately appear while the case runs, and
// goroutineStabilizeMaxWindows caps the baseline stabilization loop so a
// never-quiet test binary still terminates.
const (
	goroutineSettleSamples       = 10
	goroutineSettleInterval      = 5 * time.Millisecond
	goroutineTolerance           = 2
	goroutineStabilizeMaxWindows = 25
)

// settleMinGoroutines samples the goroutine count over one settle window and
// returns the minimum, so transient framework-parallel activity does not
// inflate the measurement.
func settleMinGoroutines() int {
	min := int(^uint(0) >> 1)
	for i := 0; i < goroutineSettleSamples; i++ {
		if n := runtime.NumGoroutine(); n < min {
			min = n
		}
		time.Sleep(goroutineSettleInterval)
	}
	return min
}

// stableBaselineGoroutines waits for the goroutine count to reach the test
// binary's steady state — two consecutive settle windows whose minima differ
// by no more than the tolerance — and returns the minimum over that stable
// pair. Under a parallel test binary the count ramps while sibling tests
// start their subtests; a baseline taken mid-ramp would misread the ramp as
// adapter activity, so the entry window must actually stabilize.
func stableBaselineGoroutines() int {
	prev := settleMinGoroutines()
	for range goroutineStabilizeMaxWindows {
		cur := settleMinGoroutines()
		if diff := cur - prev; diff <= goroutineTolerance && diff >= -goroutineTolerance {
			if cur < prev {
				return cur
			}
			return prev
		}
		prev = cur
	}
	return prev
}

// runNoBackgroundGoroutinesCase asserts that running the representative store
// operations on a fresh store spawns no background goroutines: the settle-min
// count over a single immediate window after the operations must not exceed
// the stabilized baseline by more than the tolerance. The after-window is
// deliberately not stabilized — short-lived violation goroutines must still
// be alive while it samples. The case never runs t.Parallel() — the
// measurement must be synchronous. Timer-only violations (a goroutine-less
// timer) are not observable through this window and are out of scope for
// this case.
//
// Derived from: ARCHITECTURE-SPINE.md AD-12 (operational contract — store
// adapters must not spawn background goroutines or timers).
func runNoBackgroundGoroutinesCase[T any](t *testing.T, newStore func() T, ops func(T)) {
	t.Helper()
	before := stableBaselineGoroutines()
	store := newStore()
	ops(store)
	after := settleMinGoroutines()
	if after > before+goroutineTolerance {
		t.Fatalf("goroutine count grew from %d to %d while running store operations (tolerance %d)", before, after, goroutineTolerance)
	}
}

// maybeAssertConformsTo runs the optional credential check: when the adapter
// exposes ConformsTo, its value must equal SuiteVersion.
func (o options) maybeAssertConformsTo(t *testing.T, name string, store any) {
	t.Helper()
	o.mayCase(t, name, func(t *testing.T) {
		cred, ok := store.(conformanceCredential)
		if !ok {
			return
		}
		if got := cred.ConformsTo(); got != SuiteVersion {
			t.Errorf("ConformsTo() = %q, want %q", got, SuiteVersion)
		}
	})
}
