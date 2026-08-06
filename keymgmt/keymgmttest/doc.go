// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package keymgmttest defines an executable conformance suite for the key
// record store port declared in package keymgmt. The suite pins the port
// contract in runnable form: an adapter proves compliance by passing every
// MUST-graded case, and a host verifies an adapter's credential before
// assembly.
//
// # Entry point
//
//	RunRecordStoreSuite(t *testing.T, newStore func() keymgmt.RecordStore, opts ...Option)
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
// enhanced behavior and are skipped by default; pass WithMay(true) to run
// them.
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
// The cases are derived from the six contract elements, argued from the key
// management subsystem's own needs: (1) every method takes a context first,
// with a cancelled-context read on a miss still returning ErrRecordNotFound
// and a cancelled-context write either propagating context.Canceled or
// completing observably; (2) a missing Get or Delete is ErrRecordNotFound and
// an empty store lists zero records; (3) the port declares no reclamation
// entry — retirement is driven by the manager's core-side reconciliation, so
// the suite pins retention until an explicit Delete instead; (4) Create is
// insert-only and rejects a duplicate handle or a non-retired public id,
// while a retired public id is reusable and a successful create initializes
// Version to 1; Update and Delete on a missing record return
// ErrRecordNotFound; (5) Update carries an optimistic-concurrency marker:
// a mismatched expectedVersion leaves the stored record untouched and
// returns ErrVersionConflict, a match increments the stored version and
// writes the new version back to the caller; (6) the store is time-agnostic —
// it never filters by lifecycle windows, and every Get/List result is an
// independent deep copy so caller mutation cannot corrupt stored material.
// Key material and lifecycle semantics follow RFC 7517, RFC 7518 and NIST
// SP 800-57; per-case derivation URLs accompany each case.
package keymgmttest
