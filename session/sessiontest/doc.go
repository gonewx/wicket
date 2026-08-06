// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package sessiontest defines an executable conformance suite for the session
// store port declared in package session. The suite pins the port contract in
// runnable form: an adapter proves compliance by passing every MUST-graded
// case, and a host verifies an adapter's credential before assembly.
//
// # Entry point
//
//	RunSessionStoreSuite(t *testing.T, newStore func() session.Store, opts ...Option)
//
// The factory must return a fresh empty store on every call; the suite calls
// it before each case so no state leaks between cases. The factory may open
// connections or set up fixtures as the adapter requires; the suite never
// inspects the backing medium.
//
// # Grading
//
// Cases are graded MUST or MAY. MUST cases run unconditionally; an adapter
// that skips or fails a MUST case cannot claim compliance. MAY cases cover
// enhanced behavior — the suite's own memory-store optimizations such as lazy
// reclamation, plus optional parallel stress — and are skipped by default;
// pass WithMay(true) to run them.
//
// # Compliance credential
//
// SuiteVersion identifies the contract version this suite verifies. A
// compliant adapter exposes ConformsTo() string returning the suite version
// it was verified against; a host compares adapter.ConformsTo() to
// SuiteVersion at assembly time and refuses to assemble an adapter whose
// credential does not match. An adapter without the method carries no
// credential and must not be called compliant.
//
// # Contract derivation
//
// The cases are derived from the six contract elements, argued from the
// session subsystem's own needs: (1) every method takes a context first,
// with a cancelled-context read on a miss still returning ErrSessionNotFound
// and a cancelled-context write either propagating context.Canceled or
// completing observably; (2) a missing read is ErrSessionNotFound, and an
// unknown subject yields an empty result list (nil or empty both count);
// (3) DeleteExpired is the sole reclamation entry and reclaims strictly
// before the cutoff, leaving records without an expiry untouched;
// (4) CreateSession is insert-only with a behavior-level collision error and
// no side effects, while Update/Delete/AddClientID on a missing session are
// no-ops; (5) the port carries no read-modify-write version surface, so
// concurrency safety is expressed as MAY-grade parallel stress; (6) expiry
// judgement lives in the core-side Coordinator.ValidateSession with an
// injected clock, while a store's own lazy reclamation is an opt-in MAY
// behavior. Outer logout semantics follow OpenID Connect Session Management
// and Back-Channel Logout; per-case derivation URLs accompany each case.
package sessiontest
