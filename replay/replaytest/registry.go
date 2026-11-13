// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replaytest

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
)

var mustCases = []suiteCase{
	{"RegisterFirstSucceeds", caseRegisterFirstSucceeds},
	{"RegisterDuplicateReturnsSentinel", caseRegisterDuplicateReturnsSentinel},
	{"DuplicateLeavesExpiryUnchanged", caseDuplicateLeavesExpiryUnchanged},
	{"ExpiredButUnreclaimedIsStillDuplicate", caseExpiredButUnreclaimedIsStillDuplicate},
	{"RemoveExpiredStrictlyBeforeCutoff", caseRemoveExpiredStrictlyBeforeCutoff},
	{"RemoveExpiredEmptyAndRepeat", caseRemoveExpiredEmptyAndRepeat},
	{"ReRegisterAfterReclaim", caseReRegisterAfterReclaim},
	{"DistinctKeysIndependent", caseDistinctKeysIndependent},
	{"ConcurrentRegisterSingleWinner", caseConcurrentRegisterSingleWinner},
	{"ConcurrentDistinctKeysAllSucceed", caseConcurrentDistinctKeysAllSucceed},
	{"RejectsEmptyKeyAndZeroExpiry", caseRejectsEmptyKeyAndZeroExpiry},
	{"CancelledContext", caseCancelledContext},
	{"ExpiryComparedAsInstant", caseExpiryComparedAsInstant},
	{"CredentialMatchesWhenExposed", caseCredentialMatchesWhenExposed},
}

var mayCases = []suiteCase{
	{"HighContentionSingleWinner", caseHighContentionSingleWinner},
	{"NoBackgroundGoroutines", caseNoBackgroundGoroutines},
	{"SubSecondExpiryNotRoundedDown", caseSubSecondExpiryNotRoundedDown},
}

// A key that was never registered is accepted.
func caseRegisterFirstSucceeds(t *testing.T, newRegistry func() replay.Registry) {
	registerFirst(t, newRegistry(), plainKey, at(time.Hour))
}

// A registered key is refused with the sentinel, whatever expiry instant the
// repeated call carries.
func caseRegisterDuplicateReturnsSentinel(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	registerFirst(t, registry, plainKey, at(time.Hour))
	registerDuplicate(t, registry, plainKey, at(time.Hour))
	registerDuplicate(t, registry, plainKey, at(2*time.Hour))
}

// A refused registration changes nothing: the stored expiry instant is
// neither pushed later nor pulled earlier.
func caseDuplicateLeavesExpiryUnchanged(t *testing.T, newRegistry func() replay.Registry) {
	// A later instant offered by the duplicate must not extend the record.
	registry := newRegistry()
	registerFirst(t, registry, plainKey, at(0))
	registerDuplicate(t, registry, plainKey, at(10*time.Hour))
	removeExpired(t, registry, at(time.Second), 1)
	registerFirst(t, registry, plainKey, at(time.Hour))

	// An earlier instant offered by the duplicate must not shorten it.
	registry = newRegistry()
	registerFirst(t, registry, plainKey, at(10*time.Hour))
	registerDuplicate(t, registry, plainKey, at(-10*time.Hour))
	removeExpired(t, registry, at(0), 0)
	registerDuplicate(t, registry, plainKey, at(time.Hour))
}

// A record whose expiry instant lies in the real past is recorded like any
// other and stays a duplicate until it is reclaimed. This is the only case
// that uses the past instant.
func caseExpiredButUnreclaimedIsStillDuplicate(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	registerFirst(t, registry, plainKey, pastInstant)
	registerDuplicate(t, registry, plainKey, pastInstant)
}

// RemoveExpired drops records expiring strictly before the cutoff and no
// others; a record expiring exactly at the cutoff stays.
func caseRemoveExpiredStrictlyBeforeCutoff(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	before, exact, after := plainKey, secondKey, thirdKey
	registerFirst(t, registry, before, at(-time.Second))
	registerFirst(t, registry, exact, at(0))
	registerFirst(t, registry, after, at(time.Second))

	removeExpired(t, registry, at(0), 1)
	registerFirst(t, registry, before, at(time.Hour))
	registerDuplicate(t, registry, exact, at(time.Hour))
	registerDuplicate(t, registry, after, at(time.Hour))

	removeExpired(t, registry, at(time.Second), 1)
	registerFirst(t, registry, exact, at(time.Hour))
	registerDuplicate(t, registry, after, at(time.Hour))
}

// RemoveExpired on an empty registry reports zero, and the count covers one
// call only.
func caseRemoveExpiredEmptyAndRepeat(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	removeExpired(t, registry, at(0), 0)

	registerFirst(t, registry, plainKey, at(-time.Second))
	removeExpired(t, registry, at(0), 1)
	removeExpired(t, registry, at(0), 0)
}

// A reclaimed key is gone for good: it registers again as new, and is a
// duplicate again after that.
func caseReRegisterAfterReclaim(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	registerFirst(t, registry, plainKey, at(-time.Second))
	removeExpired(t, registry, at(0), 1)
	registerFirst(t, registry, plainKey, at(time.Hour))
	registerDuplicate(t, registry, plainKey, at(time.Hour))
}

// Keys are compared in full: two keys differing in one character, at either
// end, are unrelated records.
func caseDistinctKeysIndependent(t *testing.T, newRegistry func() replay.Registry) {
	for _, neighbour := range []string{firstCharKey, lastCharKey} {
		registry := newRegistry()
		registerFirst(t, registry, plainKey, at(-time.Second))
		registerFirst(t, registry, neighbour, at(time.Hour))

		removeExpired(t, registry, at(0), 1)
		registerDuplicate(t, registry, neighbour, at(time.Hour))
		registerFirst(t, registry, plainKey, at(time.Hour))
		registerDuplicate(t, registry, neighbour, at(time.Hour))
	}
}

// Of 64 goroutines registering one key at the same moment exactly one
// succeeds and the other 63 get the sentinel, in each of 20 rounds.
func caseConcurrentRegisterSingleWinner(t *testing.T, newRegistry func() replay.Registry) {
	singleWinnerRounds(t, newRegistry, 64, 20)
}

// 64 goroutines registering 64 different keys at the same moment all succeed.
func caseConcurrentDistinctKeysAllSucceed(t *testing.T, newRegistry func() replay.Registry) {
	deadline := time.NewTimer(concurrencyTimeout)
	defer deadline.Stop()

	errs := registerTogether(t, newRegistry(), len(contentionKeys), func(i int) string { return contentionKeys[i] }, deadline.C)
	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Register of distinct keys returned %v, want nil from every call", err)
		}
	}
}

// An empty key and a zero expiry instant are refused as invalid arguments,
// not as duplicates, and leave no record.
func caseRejectsEmptyKeyAndZeroExpiry(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	invalid := []struct {
		what      string
		key       string
		expiresAt time.Time
	}{
		{"an empty key", "", at(-time.Second)},
		{"a zero expiry instant", plainKey, time.Time{}},
	}
	for _, call := range invalid {
		err := registry.Register(context.Background(), call.key, call.expiresAt)
		if !errors.Is(err, replay.ErrInvalidArgument) {
			t.Fatalf("Register with %s = %v, want an error matching replay.ErrInvalidArgument", call.what, err)
		}
		if errors.Is(err, replay.ErrDuplicateHandle) {
			t.Fatalf("Register with %s = %v, which must not match replay.ErrDuplicateHandle", call.what, err)
		}
	}
	// Anything the refused calls had recorded would be reclaimed here.
	removeExpired(t, registry, at(0), 0)
	registerFirst(t, registry, plainKey, at(time.Hour))
}

// A cancelled context may abort a call, but the abort never looks like a
// replay verdict, never lets a duplicate through and never reclaims an
// unexpired record.
func caseCancelledContext(t *testing.T, newRegistry func() replay.Registry) {
	cancelled := cancelledContext()

	// An unregistered key: either the registration takes effect, or the call
	// reports the cancellation.
	registry := newRegistry()
	err := registry.Register(cancelled, plainKey, at(time.Hour))
	switch {
	case err == nil:
		registerDuplicate(t, registry, plainKey, at(time.Hour))
	case errors.Is(err, replay.ErrDuplicateHandle):
		t.Fatalf("Register of an unregistered key with a cancelled context = %v, which must not match replay.ErrDuplicateHandle", err)
	case !errors.Is(err, context.Canceled):
		t.Fatalf("Register of an unregistered key with a cancelled context = %v, want nil or an error matching context.Canceled", err)
	}

	// A registered key: the sentinel or the cancellation, never nil.
	registry = newRegistry()
	registerFirst(t, registry, plainKey, at(time.Hour))
	err = registry.Register(cancelled, plainKey, at(time.Hour))
	if err == nil {
		t.Fatal("Register of a registered key with a cancelled context = nil, want replay.ErrDuplicateHandle or an error matching context.Canceled")
	}
	if !errors.Is(err, replay.ErrDuplicateHandle) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Register of a registered key with a cancelled context = %v, want replay.ErrDuplicateHandle or an error matching context.Canceled", err)
	}
	registerDuplicate(t, registry, plainKey, at(time.Hour))

	// RemoveExpired: it completes or reports the cancellation; either way
	// records that do not expire before the cutoff stay.
	registry = newRegistry()
	registerFirst(t, registry, plainKey, at(time.Hour))
	registerFirst(t, registry, secondKey, at(time.Hour))
	removed, err := registry.RemoveExpired(cancelled, at(time.Hour))
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("RemoveExpired with a cancelled context = (%d, %v), want a nil error or one matching context.Canceled", removed, err)
	}
	if err == nil && removed != 0 {
		t.Fatalf("RemoveExpired with a cancelled context removed %d records, but none expired before the cutoff", removed)
	}
	registerDuplicate(t, registry, plainKey, at(time.Hour))
	registerDuplicate(t, registry, secondKey, at(time.Hour))
}

// Expiry and cutoff are compared as instants: the same instant written in
// another time zone is still the same instant.
func caseExpiryComparedAsInstant(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	eastEight := time.FixedZone("", 8*60*60)
	registerFirst(t, registry, plainKey, at(0).In(eastEight))

	removeExpired(t, registry, at(0), 0)
	removeExpired(t, registry, at(time.Second), 1)
}

// A registry that exposes a compliance credential must name this suite
// version. A registry without one passes.
func caseCredentialMatchesWhenExposed(t *testing.T, newRegistry func() replay.Registry) {
	credentialed, ok := newRegistry().(interface{ ConformsTo() string })
	if !ok {
		return
	}
	if got := credentialed.ConformsTo(); got != SuiteVersion {
		t.Fatalf("ConformsTo() = %q, want SuiteVersion %q", got, SuiteVersion)
	}
}

// The single-winner case under heavier contention: 512 goroutines, 50 rounds.
func caseHighContentionSingleWinner(t *testing.T, newRegistry func() replay.Registry) {
	singleWinnerRounds(t, newRegistry, 512, 50)
}

// A registry does its work inside the calls it receives. This samples the
// goroutine count around a few calls and fails when it stays above where it
// started. It is a heuristic: it can neither see a goroutine started by the
// factory nor tell whose goroutine it counted.
func caseNoBackgroundGoroutines(t *testing.T, newRegistry func() replay.Registry) {
	const samples = 200

	registry := newRegistry()

	// Goroutines of earlier cases may still be winding down; take the lowest
	// of several samples as the starting point.
	before := runtime.NumGoroutine()
	for i := 0; i < samples; i++ {
		runtime.Gosched()
		if n := runtime.NumGoroutine(); n < before {
			before = n
		}
	}

	registerFirst(t, registry, plainKey, at(time.Hour))
	registerDuplicate(t, registry, plainKey, at(time.Hour))
	registerFirst(t, registry, secondKey, at(-time.Second))
	removeExpired(t, registry, at(0), 1)
	removeExpired(t, registry, at(0), 0)

	after := runtime.NumGoroutine()
	for i := 0; i < samples && after > before; i++ {
		runtime.Gosched()
		after = runtime.NumGoroutine()
	}
	if after > before {
		t.Fatalf("goroutine count rose from %d to %d across Register and RemoveExpired calls; a registry must not start background work", before, after)
	}
}

// A medium coarser than the instants it is given may round an expiry instant
// later, never earlier.
func caseSubSecondExpiryNotRoundedDown(t *testing.T, newRegistry func() replay.Registry) {
	registry := newRegistry()
	registerFirst(t, registry, plainKey, at(500*time.Millisecond))
	removeExpired(t, registry, at(400*time.Millisecond), 0)
	registerDuplicate(t, registry, plainKey, at(time.Hour))
}
