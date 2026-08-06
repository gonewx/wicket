// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package session_test

import (
	"testing"
	"time"

	"github.com/gonewx/wicket/session"
	"github.com/gonewx/wicket/session/sessiontest"
)

// wiringClock is the deterministic time source the in-repo memory store is
// wired with. Tests never consult the real clock, so every suite run is
// deterministic regardless of when it executes.
type wiringClock struct {
	at time.Time
}

func (c wiringClock) Now() time.Time { return c.at }

var fixedWiringClock = wiringClock{at: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)}

// TestMemoryStoreConformanceE2E wires the in-repo memory store into the
// session conformance suite, MUST and MAY alike. The suite is the executable
// definition of the session.Store port; the store must satisfy every case.
func TestMemoryStoreConformanceE2E(t *testing.T) {
	t.Parallel()
	sessiontest.RunSessionStoreSuite(t, func() session.Store {
		return session.NewMemoryStore(fixedWiringClock)
	}, sessiontest.WithMay(true))
}
