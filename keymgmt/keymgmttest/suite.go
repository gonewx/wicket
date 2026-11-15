// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package keymgmttest

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/gonewx/wicket/keymgmt"
)

// SuiteVersion identifies the contract version this suite verifies. A
// compliant adapter exposes ConformsTo() string returning this value; a host
// compares adapter.ConformsTo() to SuiteVersion at assembly time. The three
// suite packages (storagetest, sessiontest, keymgmttest) step this value in
// lockstep so a host validates a single number at assembly.
const SuiteVersion = "2.0.0"

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
			t.Skip("MAY case skipped; pass keymgmttest.WithMay(true)")
		}
		fn(t)
	})
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// goroutineTolerance absorbs unrelated test-framework parallelism that can
// legitimately appear between the two boundary samples of one
// no-background-activity repetition. noBackgroundGoroutineIterations repeats
// the operation sequence so the growth statistic is the minimum over several
// independent samples: a violating store bumps the count on every repetition
// (its goroutines outlive the sampling span), while a sibling-test burst
// that happens to collide with a single window is excluded by the minimum.
// noBackgroundGoroutineSpacing decorrelates the repetitions from the test
// framework's parallel drain.
const (
	goroutineTolerance              = 2
	noBackgroundGoroutineIterations = 4
	noBackgroundGoroutineSpacing    = 2 * time.Millisecond
)

// assertNoBackgroundGoroutines asserts that running the representative store
// operations on fresh stores spawns no background goroutines: the count is
// sampled at the operation boundary, immediately before and after each ops
// block. A go statement registers its goroutine synchronously, so a store
// that spawns background work shows the bump in the after sample. Sampling at
// the boundary instead of over a settle window keeps sibling-test activity
// out of the measurement: in a parallel test binary the count is persistently
// elevated by running siblings (observed +39 against a +2 tolerance), while
// the ops block itself takes microseconds. The minimum across the repetitions
// rejects sibling bursts that collide with an individual window. The case
// never runs t.Parallel() — the measurement must be synchronous. Timer-only
// violations (a goroutine-less timer) are not observable through the count
// and are out of scope for this case.
//
// Derived from: ARCHITECTURE-SPINE.md AD-12 (operational contract — store
// adapters must not spawn background goroutines or timers).
func assertNoBackgroundGoroutines[T any](t *testing.T, newStore func() T, ops func(T)) {
	t.Helper()
	minGrowth := int(^uint(0) >> 1)
	for i := 0; i < noBackgroundGoroutineIterations; i++ {
		store := newStore()
		atStart := runtime.NumGoroutine()
		ops(store)
		after := runtime.NumGoroutine()
		if growth := after - atStart; growth < minGrowth {
			minGrowth = growth
		}
		if i+1 < noBackgroundGoroutineIterations {
			time.Sleep(noBackgroundGoroutineSpacing)
		}
	}
	if minGrowth > goroutineTolerance {
		t.Fatalf("goroutine count grew by %d while running store operations (tolerance %d)", minGrowth, goroutineTolerance)
	}
}

func expectRecordNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, keymgmt.ErrRecordNotFound) {
		t.Fatalf("error = %v, want keymgmt.ErrRecordNotFound", err)
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
