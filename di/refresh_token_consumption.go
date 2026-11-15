// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package di

import (
	"fmt"

	"github.com/gonewx/wicket/services"
)

// SetRefreshTokenConsumption declares what happens to the refresh token of a
// client with one-time refresh tokens once it is redeemed. The default,
// services.RefreshTokenKeptOnRedemption, keeps the token and returns its
// handle again. services.RefreshTokenRemovedOnRedemption and
// services.RefreshTokenMarkedOnRedemption issue a new handle on every
// redemption and remove the redeemed record or keep it marked as consumed;
// a marked token presented again by its client revokes the refresh tokens
// issued after it. Clients that reuse their refresh tokens are not affected.
// It must be called before Freeze and panics on an undeclared value.
func (c *ServerConfig) SetRefreshTokenConsumption(consumption services.RefreshTokenConsumption) {
	if c.frozen {
		panic("SetRefreshTokenConsumption must not be called after Freeze")
	}
	if !consumption.Valid() {
		panic(fmt.Sprintf("SetRefreshTokenConsumption: undeclared value %d", int(consumption)))
	}
	c.refreshTokenConsumption = consumption
}

// RefreshTokenConsumption reports the declared refresh token consumption.
func (c *ServerConfig) RefreshTokenConsumption() services.RefreshTokenConsumption {
	if c == nil {
		return services.RefreshTokenKeptOnRedemption
	}
	return c.refreshTokenConsumption
}
