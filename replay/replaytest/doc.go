// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package replaytest defines an executable conformance suite for the replay
// registry port declared in package replay. An adapter proves compliance by
// passing every MUST-graded case; a host checks the adapter's credential
// before assembly.
//
// # Entry point
//
//	RunRegistrySuite(t *testing.T, newRegistry func() replay.Registry, opts ...Option)
//
// The factory must return a new, empty registry on every call. The suite
// calls it at least once per case and shares no state between cases. The
// adapter's own test prepares whatever the medium needs (a container, a
// schema, a fixture) and then calls RunRegistrySuite; the suite never
// inspects the medium.
//
// # Grading
//
// MUST cases run as subtests named MUST/<case>. They always run. MAY cases
// run as subtests named MAY/<case> and only with WithMay(true); without it
// they are not registered at all. MAY covers heavier contention, a heuristic
// check for background goroutines and sub-second expiry instants.
//
// # Compliance credential
//
// SuiteVersion identifies the contract version this suite verifies. It is
// versioned on its own, starting at 1.0.0: it does not move together with
// the storagetest, sessiontest and keymgmttest versions, and those do not
// move with it. A replay registry adapter is a store type of its own and
// exposes ConformsTo() string returning the SuiteVersion it was verified
// against. A host compares adapter.ConformsTo() with replaytest.SuiteVersion
// for equality, separately from every other suite version, and refuses an
// adapter whose credential differs. The suite itself checks the credential
// of a registry that exposes one.
//
// # Time
//
// The suite never reads a clock and never waits for anything to expire.
// Every instant is a fixed constant: a base instant of
// 2100-01-01T00:00:00Z with offsets of at most ten hours either way, and
// one instant in the real past, 2001-01-01T00:00:00Z, used by a single case.
// "Expired" only ever means "before the cutoff passed to RemoveExpired". An
// adapter must therefore be able to store and compare instants up to
// 2100-01-01T10:00:00Z. Keys are fixed 64-character lowercase hexadecimal
// literals; test vectors for replay.Key are available from KeyVectors.
//
// # Contract derivation
//
// The cases follow from six questions asked of this port alone. (1) Context:
// registering happens on the request path of a protocol endpoint, so the
// caller owns the deadline and both methods take a context first; a
// cancelled context may abort a call but must never turn into a replay
// verdict. (2) Missing records: the port has no read, so nothing can be
// "not found" and there is no such error. (3) Reclaiming: records have a
// lifetime, and RemoveExpired, driven by the host, is the only way they
// leave; it drops what expires strictly before the cutoff. (4) Writes:
// Register is insert-only, which is the whole correctness of the port — a
// duplicate changes nothing, not even the expiry instant. (5) Concurrency:
// there is no read-modify-write and so no version argument; exactly one of
// any number of concurrent registrations of a key succeeds. (6) Expiry: the
// registry does not judge it. A record past its expiry instant is still a
// duplicate until it is reclaimed.
//
// # What passing does not prove
//
// Two hard requirements of the port are beyond what the suite can pin down.
// Atomicity: ConcurrentRegisterSingleWinner releases 64 goroutines at once,
// twenty times over, which exposes a check-then-write whose window is as
// wide as a network or disk round trip but has next to no chance against a
// window of nanoseconds. Passing it is not evidence of atomicity; an adapter
// has to get that from an atomic primitive of its medium, such as an insert
// under a unique constraint or a conditional write. Native expiry: because
// the suite does not wait, it cannot observe a medium that silently drops a
// record at some future instant. Passing the suite is not evidence that an
// adapter keeps clear of native expiry or eviction either.
package replaytest
