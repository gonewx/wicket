// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package replay_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/replay/replaytest"
)

const memoryTestKey = "5b1d1f0e3c2a49786f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0918"

var memoryTestInstant = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)

func TestMemoryRegistryPassesSuite(t *testing.T) {
	replaytest.RunRegistrySuite(t, func() replay.Registry { return replay.NewMemoryRegistry() }, replaytest.WithMay(true))
}

// The memory registry is a single-process registry: it carries no compliance
// credential a host could mistake for a production one, and it holds nothing
// to release.
func TestMemoryRegistryHasNoCredentialAndNoCloser(t *testing.T) {
	var registry any = replay.NewMemoryRegistry()
	if _, ok := registry.(interface{ ConformsTo() string }); ok {
		t.Error("MemoryRegistry exposes ConformsTo()")
	}
	if _, ok := registry.(io.Closer); ok {
		t.Error("MemoryRegistry is an io.Closer")
	}
}

func TestMemoryRegistriesAreIndependent(t *testing.T) {
	first, second := replay.NewMemoryRegistry(), replay.NewMemoryRegistry()
	if err := first.Register(context.Background(), memoryTestKey, memoryTestInstant); err != nil {
		t.Fatalf("Register on the first registry = %v", err)
	}
	if err := second.Register(context.Background(), memoryTestKey, memoryTestInstant); err != nil {
		t.Fatalf("Register on the second registry = %v, want nil: registries share no records", err)
	}
}

// With a context that is already done the memory registry changes nothing
// and returns the context's error.
func TestMemoryRegistryDoneContextChangesNothing(t *testing.T) {
	ctx := context.Background()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	registry := replay.NewMemoryRegistry()
	if err := registry.Register(cancelled, memoryTestKey, memoryTestInstant); !errors.Is(err, context.Canceled) {
		t.Fatalf("Register with a cancelled context = %v, want context.Canceled", err)
	}
	if err := registry.Register(ctx, memoryTestKey, memoryTestInstant); err != nil {
		t.Fatalf("Register after the cancelled attempt = %v, want nil: the attempt must not have registered the key", err)
	}

	if err := registry.Register(cancelled, memoryTestKey, memoryTestInstant); !errors.Is(err, context.Canceled) {
		t.Fatalf("Register of a registered key with a cancelled context = %v, want context.Canceled", err)
	}

	removed, err := registry.RemoveExpired(cancelled, memoryTestInstant.Add(time.Hour))
	if !errors.Is(err, context.Canceled) || removed != 0 {
		t.Fatalf("RemoveExpired with a cancelled context = (%d, %v), want (0, context.Canceled)", removed, err)
	}
	if err := registry.Register(ctx, memoryTestKey, memoryTestInstant); !errors.Is(err, replay.ErrDuplicateHandle) {
		t.Fatalf("Register after the cancelled RemoveExpired = %v, want replay.ErrDuplicateHandle: nothing may have been removed", err)
	}

	expired, deadlineCancel := context.WithDeadline(ctx, time.Unix(0, 0))
	defer deadlineCancel()
	if err := replay.NewMemoryRegistry().Register(expired, memoryTestKey, memoryTestInstant); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Register with an expired deadline = %v, want context.DeadlineExceeded", err)
	}
}

// Invalid arguments together with a cancelled context: whichever error wins,
// the call is neither a success nor a replay verdict, and it records nothing.
func TestMemoryRegistryInvalidArgumentsWithCancelledContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	registry := replay.NewMemoryRegistry()
	calls := []struct {
		name      string
		key       string
		expiresAt time.Time
	}{
		{"empty key", "", memoryTestInstant},
		{"zero expiry", memoryTestKey, time.Time{}},
	}
	for _, call := range calls {
		err := registry.Register(cancelled, call.key, call.expiresAt)
		if err == nil {
			t.Fatalf("%s: Register = nil, want an error", call.name)
		}
		if errors.Is(err, replay.ErrDuplicateHandle) {
			t.Fatalf("%s: Register = %v, which must not match replay.ErrDuplicateHandle", call.name, err)
		}
		if !errors.Is(err, replay.ErrInvalidArgument) && !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: Register = %v, want replay.ErrInvalidArgument or context.Canceled", call.name, err)
		}
	}

	if removed, err := registry.RemoveExpired(context.Background(), memoryTestInstant.Add(time.Hour)); removed != 0 || err != nil {
		t.Fatalf("RemoveExpired after refused calls = (%d, %v), want (0, nil): they must record nothing", removed, err)
	}
	if err := registry.Register(context.Background(), memoryTestKey, memoryTestInstant); err != nil {
		t.Fatalf("Register after refused calls = %v, want nil", err)
	}
}

// A zero cutoff is not special: nothing expires before it.
func TestMemoryRegistryZeroCutoffRemovesNothing(t *testing.T) {
	registry := replay.NewMemoryRegistry()
	if err := registry.Register(context.Background(), memoryTestKey, time.Unix(1, 0)); err != nil {
		t.Fatalf("Register = %v", err)
	}
	if removed, err := registry.RemoveExpired(context.Background(), time.Time{}); removed != 0 || err != nil {
		t.Fatalf("RemoveExpired with a zero cutoff = (%d, %v), want (0, nil)", removed, err)
	}
}

// The zero value works as an empty registry.
func TestMemoryRegistryZeroValueIsUsable(t *testing.T) {
	var registry replay.MemoryRegistry
	ctx := context.Background()

	if removed, err := registry.RemoveExpired(ctx, memoryTestInstant); removed != 0 || err != nil {
		t.Fatalf("RemoveExpired on the zero value = (%d, %v), want (0, nil)", removed, err)
	}
	if err := registry.Register(ctx, memoryTestKey, memoryTestInstant); err != nil {
		t.Fatalf("first Register on the zero value returned %v, want nil", err)
	}
	if err := registry.Register(ctx, memoryTestKey, memoryTestInstant); !errors.Is(err, replay.ErrDuplicateHandle) {
		t.Fatalf("second Register on the zero value returned %v, want replay.ErrDuplicateHandle", err)
	}
}
