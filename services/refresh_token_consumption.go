// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package services

import "fmt"

// RefreshTokenConsumption decides what happens to a one-time refresh token
// (a client whose RefreshTokenUsage is TokenUsageOneTimeOnly) once it has
// been redeemed. Clients that reuse their refresh tokens are never affected.
type RefreshTokenConsumption int

const (
	// RefreshTokenKeptOnRedemption is the zero value: the refresh token is
	// updated in place and its handle is returned again, so the same handle
	// stays redeemable.
	RefreshTokenKeptOnRedemption RefreshTokenConsumption = iota
	// RefreshTokenRemovedOnRedemption issues a new handle on every
	// redemption and removes the redeemed record. A replayed handle is
	// refused, but nothing links it to its successor any more.
	RefreshTokenRemovedOnRedemption
	// RefreshTokenMarkedOnRedemption issues a new handle on every
	// redemption and keeps the redeemed record, marked as consumed and
	// linked to its successor. When the client the token was issued to
	// presents a consumed token again, the refresh tokens still valid down
	// that link are revoked as well.
	RefreshTokenMarkedOnRedemption
)

// Valid reports whether c is one of the declared values.
func (c RefreshTokenConsumption) Valid() bool {
	switch c {
	case RefreshTokenKeptOnRedemption, RefreshTokenRemovedOnRedemption, RefreshTokenMarkedOnRedemption:
		return true
	}
	return false
}

// Rotates reports whether redeeming a one-time refresh token issues a new
// handle.
func (c RefreshTokenConsumption) Rotates() bool {
	return c == RefreshTokenRemovedOnRedemption || c == RefreshTokenMarkedOnRedemption
}

func (c RefreshTokenConsumption) String() string {
	switch c {
	case RefreshTokenKeptOnRedemption:
		return "kept"
	case RefreshTokenRemovedOnRedemption:
		return "removed"
	case RefreshTokenMarkedOnRedemption:
		return "marked"
	}
	return fmt.Sprintf("RefreshTokenConsumption(%d)", int(c))
}
