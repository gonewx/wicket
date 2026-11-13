// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replaytest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
)

// flaw selects the one contract rule a fakeRegistry breaks. flawNone is the
// reference double the suite must accept; every other value is a bad double
// the suite must reject.
type flaw int

const (
	flawNone flaw = iota
	// Checks and writes in two steps, so concurrent callers can all pass the
	// check.
	flawCheckThenWrite
	// Reads its own clock and treats a record past its expiry instant as
	// absent.
	flawForgetsExpiredByOwnClock
	// Overwrites a registered key and reports success.
	flawUpsert
	// Reports a duplicate with an error that is not the sentinel.
	flawForeignDuplicateError
	// Reports the sentinel but replaces the stored expiry instant.
	flawDuplicateOverwritesExpiry
	// RemoveExpired drops every record.
	flawRemovesEverything
	// RemoveExpired also drops records expiring exactly at the cutoff.
	flawInclusiveCutoff
	// Reads its own clock and refuses an expiry instant that has passed.
	flawRefusesPastExpiry
	// Records a zero expiry instant.
	flawAcceptsZeroExpiry
	// Exposes a credential naming another suite version.
	flawStaleCredential
)

// meetTimeout is how long a flawCheckThenWrite caller waits for a second
// caller before writing alone, which is what lets sequential calls proceed.
const meetTimeout = 10 * time.Millisecond

var errForeignDuplicate = errors.New("fake: key already present")

type fakeEntry struct {
	key       string
	expiresAt time.Time
}

// fakeRegistry is a small registry over a slice, written for the suite's own
// tests and sharing nothing with replay.MemoryRegistry. It ignores context
// cancellation and completes every call, and it wraps the errors it returns,
// so the suite's errors.Is matching is exercised.
type fakeRegistry struct {
	flaw    flaw
	mu      sync.Mutex
	entries []fakeEntry
	// meet pairs up flawCheckThenWrite callers between check and write.
	meet chan struct{}
}

func newFakeRegistry(f flaw) *fakeRegistry {
	return &fakeRegistry{flaw: f, meet: make(chan struct{})}
}

// indexOf returns the position of key, or -1. The caller holds mu.
func (f *fakeRegistry) indexOf(key string) int {
	for i, entry := range f.entries {
		if entry.key == key {
			return i
		}
	}
	return -1
}

func (f *fakeRegistry) Register(_ context.Context, key string, expiresAt time.Time) error {
	if key == "" || (expiresAt.IsZero() && f.flaw != flawAcceptsZeroExpiry) {
		return fmt.Errorf("fake: %w", replay.ErrInvalidArgument)
	}
	if f.flaw == flawRefusesPastExpiry && expiresAt.Before(time.Now()) {
		return errors.New("fake: expiry instant has passed")
	}
	if f.flaw == flawCheckThenWrite {
		return f.registerCheckThenWrite(key, expiresAt)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.indexOf(key)
	if i >= 0 && f.flaw == flawForgetsExpiredByOwnClock && f.entries[i].expiresAt.Before(time.Now()) {
		f.entries = append(f.entries[:i], f.entries[i+1:]...)
		i = -1
	}
	if i < 0 {
		f.entries = append(f.entries, fakeEntry{key: key, expiresAt: expiresAt})
		return nil
	}
	switch f.flaw {
	case flawUpsert:
		f.entries[i].expiresAt = expiresAt
		return nil
	case flawForeignDuplicateError:
		return errForeignDuplicate
	case flawDuplicateOverwritesExpiry:
		f.entries[i].expiresAt = expiresAt
	}
	return fmt.Errorf("fake: %w", replay.ErrDuplicateHandle)
}

// registerCheckThenWrite is the non-atomic registration. Between its check
// and its write it waits until a second caller has also finished a check, so
// concurrent registrations of one key interleave every time instead of only
// when the scheduler happens to allow it. Callers are paired regardless of
// key; a caller that finds nobody within meetTimeout writes alone.
func (f *fakeRegistry) registerCheckThenWrite(key string, expiresAt time.Time) error {
	f.mu.Lock()
	present := f.indexOf(key) >= 0
	f.mu.Unlock()
	if present {
		return fmt.Errorf("fake: %w", replay.ErrDuplicateHandle)
	}

	wait := time.NewTimer(meetTimeout)
	defer wait.Stop()
	select {
	case f.meet <- struct{}{}:
	case <-f.meet:
	case <-wait.C:
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if i := f.indexOf(key); i >= 0 {
		f.entries[i].expiresAt = expiresAt
	} else {
		f.entries = append(f.entries, fakeEntry{key: key, expiresAt: expiresAt})
	}
	return nil
}

func (f *fakeRegistry) RemoveExpired(_ context.Context, cutoff time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	kept := make([]fakeEntry, 0, len(f.entries))
	for _, entry := range f.entries {
		expired := entry.expiresAt.Before(cutoff)
		switch f.flaw {
		case flawRemovesEverything:
			expired = true
		case flawInclusiveCutoff:
			expired = !entry.expiresAt.After(cutoff)
		}
		if !expired {
			kept = append(kept, entry)
		}
	}
	removed := len(f.entries) - len(kept)
	f.entries = kept
	return removed, nil
}

// ConformsTo is the compliance credential an adapter exposes.
func (f *fakeRegistry) ConformsTo() string {
	if f.flaw == flawStaleCredential {
		return "0.9.0"
	}
	return SuiteVersion
}

// The reference double passes every case, MAY included.
func TestReferenceDoublePassesSuite(t *testing.T) {
	RunRegistrySuite(t, func() replay.Registry { return newFakeRegistry(flawNone) }, WithMay(true))
}
