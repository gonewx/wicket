// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package storage

import (
	"net/url"
	"testing"
)

// TestConsentMessageKeyDerivation pins the properties the write side and the
// callback read side both depend on: determinism across parameter insertion
// order, sensitivity to subject and parameters, and the exact derivation
// format. The golden value fails the build of any format change that would
// silently orphan answers stored under the previous derivation.
func TestConsentMessageKeyDerivation(t *testing.T) {
	t.Parallel()

	base := url.Values{"client_id": {"client"}, "scope": {"openid"}}
	reordered := url.Values{"scope": {"openid"}, "client_id": {"client"}}
	if ConsentMessageKey("alice", base) != ConsentMessageKey("alice", reordered) {
		t.Fatalf("key differs across parameter insertion order")
	}
	if ConsentMessageKey("alice", base) == ConsentMessageKey("bob", base) {
		t.Fatalf("key does not distinguish subjects")
	}
	other := url.Values{"client_id": {"client"}, "scope": {"openid profile"}}
	if ConsentMessageKey("alice", base) == ConsentMessageKey("alice", other) {
		t.Fatalf("key does not distinguish request parameters")
	}
	if got, want := ConsentMessageKey("alice", base), "iky0dq-NBVFWl69xJ-N6gWbqRZsVQ5p8jWD4QY_4ZUg"; got != want {
		t.Fatalf("derivation format changed: got %q, want %q", got, want)
	}
}
