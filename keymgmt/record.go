// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

// Package keymgmt provides autonomous signing key material management: a
// four-phase key lifecycle, idempotent rotation, a single signing-selection
// rule, and JWKS-facing validation material. It is inert unless enabled, in
// which case it becomes the exclusive source of signing credentials while host
// validation stores continue to aggregate into JWKS output.
package keymgmt

import (
	"errors"
	"time"
)

// Phase is a key's lifecycle position. The four phases below are the complete
// state set; "deactivation" and "expiry" are events that drive the active ->
// retained transition, not phases of their own.
type Phase string

const (
	// PhaseCandidate is a key that has been created and published to JWKS but is
	// not yet eligible to sign; it warms up until its NotBefore and the
	// pre-publish window are satisfied.
	PhaseCandidate Phase = "candidate"
	// PhaseActive is a key eligible to sign within its signing window.
	PhaseActive Phase = "active"
	// PhaseRetained is a key that no longer signs but whose public material stays
	// published so already-issued tokens remain verifiable.
	PhaseRetained Phase = "retained"
	// PhaseRetired is a key that neither signs nor appears in JWKS.
	PhaseRetired Phase = "retired"
)

// PurposeTokenSigning is the first-phase key purpose: signing issued tokens.
const PurposeTokenSigning = "token_signing"

// Record is one key's persisted state: identity, material, algorithm, lifecycle
// window and concurrency marker. Public material is stored in the clear; private
// material is stored protected.
type Record struct {
	// Handle is the internal stable identifier used for audit, cache and storage
	// lookup. It is distinct from the public JWKS key id.
	Handle string
	// PublicID is the public JWKS kid used to match a token header to a key.
	PublicID string
	// Purpose constrains what the key may be used for.
	Purpose string
	// Algorithm is the JWA algorithm identifier the key signs or verifies with.
	Algorithm string
	// Phase is the current lifecycle position.
	Phase Phase
	// Priority breaks ties during signing selection; larger wins.
	Priority int
	// CreatedAt is when the record was first created.
	CreatedAt time.Time
	// NotBefore is the lower bound of the signing window; zero means no lower
	// bound (effective from creation).
	NotBefore time.Time
	// NotAfter is the upper bound of the signing window; zero means the key does
	// not expire by time and leaves active only on an explicit deactivation.
	NotAfter time.Time
	// RetainUntil is when a retained key retires; zero means unset until it is
	// computed at the moment the key enters the retained phase.
	RetainUntil time.Time
	// PublicMaterial is the PKIX-encoded public key.
	PublicMaterial []byte
	// ProtectedPrivateMaterial is the protected PKCS#8-encoded private key.
	ProtectedPrivateMaterial []byte
	// CertificateChain is an optional DER certificate chain carrier.
	CertificateChain [][]byte
	// Format tags the protection scheme of ProtectedPrivateMaterial. It is
	// independent of Version and lets a later protection scheme coexist with
	// records written under an earlier one.
	Format string
	// Version is the storage optimistic-concurrency marker; it increments on
	// every write. It is independent of the protection format tag in Format.
	Version uint64
}

// Clock is an injectable time source. All lifecycle decisions read it rather
// than the wall clock so behaviour is deterministic under test.
type Clock interface {
	Now() time.Time
}

// Entropy is an injectable random source used for key generation. It matches
// the standard io.Reader shape so crypto/rand.Reader satisfies it directly.
type Entropy interface {
	Read(p []byte) (n int, err error)
}

// RecordStore persists key records with an optimistic-concurrency marker so
// concurrent instances can rotate without producing duplicate keys.
type RecordStore interface {
	// List returns independent copies of all records.
	List() ([]*Record, error)
	// Get returns an independent copy of the record with the given handle, or
	// ErrRecordNotFound.
	Get(handle string) (*Record, error)
	// Create inserts a new record. It fails with ErrDuplicateKey if the handle or
	// a non-retired public id already exists.
	Create(record *Record) error
	// Update writes record only when expectedVersion matches the stored version,
	// then increments the stored version. A mismatch returns ErrVersionConflict.
	Update(record *Record, expectedVersion uint64) error
	// Delete removes the record with the given handle.
	Delete(handle string) error
}

var (
	// ErrRecordNotFound is returned when a lookup misses.
	ErrRecordNotFound = errors.New("keymgmt: key record not found")
	// ErrDuplicateKey is returned when a create collides on handle or public id.
	ErrDuplicateKey = errors.New("keymgmt: duplicate key record")
	// ErrVersionConflict is returned when an optimistic-concurrency update loses.
	ErrVersionConflict = errors.New("keymgmt: key record version conflict")
	// ErrNoSigningKey is returned when no active key can sign.
	ErrNoSigningKey = errors.New("keymgmt: no signing key available")
	// ErrAlgorithmUnavailable is returned when the requested algorithm has no
	// usable active key.
	ErrAlgorithmUnavailable = errors.New("keymgmt: no signing key for requested algorithm")
	// ErrConfiguration is returned when the manager configuration is invalid.
	ErrConfiguration = errors.New("keymgmt: invalid key management configuration")
	// ErrProtectorUnavailable is returned when private material cannot be
	// protected, so no key may be created or signed with.
	ErrProtectorUnavailable = errors.New("keymgmt: key protector unavailable")
)

// validateWindow enforces the field-order invariant on the non-zero bounds of a
// record: NotBefore <= NotAfter <= RetainUntil. A zero bound is unconstrained.
func validateWindow(r *Record) error {
	if !r.NotBefore.IsZero() && !r.NotAfter.IsZero() && r.NotAfter.Before(r.NotBefore) {
		return ErrConfiguration
	}
	if !r.NotAfter.IsZero() && !r.RetainUntil.IsZero() && r.RetainUntil.Before(r.NotAfter) {
		return ErrConfiguration
	}
	if !r.NotBefore.IsZero() && !r.RetainUntil.IsZero() && r.RetainUntil.Before(r.NotBefore) {
		return ErrConfiguration
	}
	return nil
}

// withinSigningWindow reports whether now lies in [NotBefore, NotAfter) using no
// skew. Signing is conservative: a key that is not yet valid or already expired
// is never chosen.
func (r *Record) withinSigningWindow(now time.Time) bool {
	if !r.NotBefore.IsZero() && now.Before(r.NotBefore) {
		return false
	}
	if !r.NotAfter.IsZero() && !now.Before(r.NotAfter) {
		return false
	}
	return true
}

// withinPublishWindow reports whether the key should appear in JWKS at now,
// widening both bounds by skew so verifiers with skewed clocks can still resolve
// the kid.
func (r *Record) withinPublishWindow(now time.Time, skew time.Duration) bool {
	if !r.NotBefore.IsZero() && now.Before(r.NotBefore.Add(-skew)) {
		return false
	}
	if r.Phase == PhaseRetained && !r.RetainUntil.IsZero() && !now.Before(r.RetainUntil.Add(skew)) {
		return false
	}
	return true
}

func copyRecord(r *Record) *Record {
	if r == nil {
		return nil
	}
	clone := *r
	clone.PublicMaterial = append([]byte(nil), r.PublicMaterial...)
	clone.ProtectedPrivateMaterial = append([]byte(nil), r.ProtectedPrivateMaterial...)
	if r.CertificateChain != nil {
		clone.CertificateChain = make([][]byte, len(r.CertificateChain))
		for i, c := range r.CertificateChain {
			clone.CertificateChain[i] = append([]byte(nil), c...)
		}
	}
	return &clone
}
