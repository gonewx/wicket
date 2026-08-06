// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package sessiontest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gonewx/wicket/session"
)

// SuiteVersion identifies the contract version this suite verifies. A
// compliant adapter exposes ConformsTo() string returning this value; a host
// compares adapter.ConformsTo() to SuiteVersion at assembly time. The three
// suite packages (storagetest, sessiontest, keymgmttest) step this value in
// lockstep so a host validates a single number at assembly.
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
			t.Skip("MAY case skipped; pass sessiontest.WithMay(true)")
		}
		fn(t)
	})
}

// suiteClock is the deterministic time source the suite injects into
// core-side components. The suite never consults the real clock, so every run
// is deterministic regardless of when it executes.
type suiteClock struct {
	at time.Time
}

func (c suiteClock) Now() time.Time { return c.at }

// Fixed time basis for expiry-semantics cases.
var (
	fixedNow     = time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	fixedPast    = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	fixedFuture  = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	suiteClockAt = suiteClock{at: fixedNow}
)

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expectSessionNotFound(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("error = %v, want session.ErrSessionNotFound", err)
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
			t.Fatalf("write reported success but the session is not observable: %v", obsErr)
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
