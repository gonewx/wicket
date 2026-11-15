// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package refreshrotation

import (
	"testing"

	"github.com/gonewx/wicket/services"
	storage_impl "github.com/gonewx/wicket/storage/impl"
)

// A refresh token is redeemed only by the client it was issued to (RFC 6749
// §6), under every consumption declaration; the refusal leaves the token
// usable by its own client.
func TestRefreshTokenOfAnotherClientIsRefused(t *testing.T) {
	cases := map[string]*services.RefreshTokenConsumption{
		"undeclared": nil,
		"kept":       new(services.RefreshTokenKeptOnRedemption),
		"removed":    new(services.RefreshTokenRemovedOnRedemption),
		"marked":     new(services.RefreshTokenMarkedOnRedemption),
	}
	for name, consumption := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, storage_impl.NewRefreshTokenStore(), consumption)
			refresh := f.issue(t, oneTimeClient)

			f.requireRefused(t, otherOneTimeClient, refresh)
			f.requireRefused(t, reuseClient, refresh)
			f.redeem(t, oneTimeClient, refresh)
		})
	}
}
