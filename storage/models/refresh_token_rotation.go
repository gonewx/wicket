// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package models

// RefreshTokenRotation links a consumed refresh token to the one issued in
// its place.
type RefreshTokenRotation struct {
	// RotatedTo is the handle of the refresh token issued when this one was
	// redeemed. It is written only when the host keeps redeemed refresh
	// tokens marked as consumed (ConsumedTime set) and is "" otherwise,
	// including on a token that was revoked rather than redeemed. A
	// persistence adapter has to keep this field; losing it keeps a replay
	// from revoking the tokens issued after the replayed one.
	RotatedTo string
}
