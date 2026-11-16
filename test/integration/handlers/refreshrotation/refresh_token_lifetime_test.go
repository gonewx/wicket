// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package refreshrotation

import (
	"context"
	"testing"
	"time"

	"github.com/gonewx/godi"
	"github.com/stretchr/testify/require"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/services"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	storage_models "github.com/gonewx/wicket/storage/models"
	integration_common "github.com/gonewx/wicket/test/integration/common"
)

const (
	// absoluteClient's refresh tokens expire 10 minutes after issue.
	absoluteClient = "lifetime.absolute"
	// slidingClient's refresh tokens expire 4 minutes after their last
	// redemption, and at the latest 10 minutes after issue.
	slidingClient = "lifetime.sliding"
)

func lifetimeClients() []*storage_models.Client {
	absolute := client(absoluteClient, wicket.TokenUsageReUse)
	absolute.RefreshTokenExpiration = wicket.TokenExpirationAbsolute
	absolute.AbsoluteRefreshTokenLifetime = 600

	sliding := client(slidingClient, wicket.TokenUsageReUse)
	sliding.RefreshTokenExpiration = wicket.TokenExpirationSliding
	sliding.SlidingRefreshTokenLifetime = 240
	sliding.AbsoluteRefreshTokenLifetime = 600
	return []*storage_models.Client{absolute, sliding}
}

// agingStore makes the refresh tokens it holds older as the test advances
// its clock. The container gives the refresh token service the system clock
// and offers no seam to replace it, so instead of moving the service's clock
// forward the store moves every creation time it hands out backward by the
// same amount, and forward again when the record is written back: the
// service then sees each record exactly as old as the adjustable clock says.
// The wall clock still runs between requests, by milliseconds, so the
// assertions stay a minute away from every expiry.
type agingStore struct {
	*storage_impl.RefreshTokenStore
	clock *integration_common.AdjustableClock
	start time.Time
}

func newAgingStore(clock *integration_common.AdjustableClock) *agingStore {
	return &agingStore{RefreshTokenStore: storage_impl.NewRefreshTokenStore(), clock: clock, start: clock.Now()}
}

func (s *agingStore) age() time.Duration { return s.clock.Now().Sub(s.start) }

// shifted runs write with the creation time of token moved by d, restoring
// it afterwards; a record without a creation time is left as it is.
func shifted(token *storage_models.RefreshToken, d time.Duration, write func() error) error {
	if token == nil || token.CreationTime.IsZero() {
		return write()
	}
	original := token.CreationTime
	token.CreationTime = original.Add(d)
	defer func() { token.CreationTime = original }()
	return write()
}

func (s *agingStore) StoreRefreshToken(ctx context.Context, handle string, token *storage_models.RefreshToken) error {
	return shifted(token, s.age(), func() error { return s.RefreshTokenStore.StoreRefreshToken(ctx, handle, token) })
}

func (s *agingStore) UpdateRefreshToken(ctx context.Context, handle string, token *storage_models.RefreshToken, expectedVersion int) error {
	return shifted(token, s.age(), func() error {
		return s.RefreshTokenStore.UpdateRefreshToken(ctx, handle, token, expectedVersion)
	})
}

func (s *agingStore) GetRefreshToken(ctx context.Context, handle string) (*storage_models.RefreshToken, error) {
	token, err := s.RefreshTokenStore.GetRefreshToken(ctx, handle)
	if err == nil && !token.CreationTime.IsZero() {
		token.CreationTime = token.CreationTime.Add(-s.age())
	}
	return token, err
}

// AC1: a refresh token survives RemoveExpired(now) run by the host right
// after issue, under the default client lifetime, and is redeemed after it.
func TestRefreshTokenSurvivesHostCleanup(t *testing.T) {
	store := storage_impl.NewRefreshTokenStore()
	f := newFixture(t, store, nil)
	refresh := f.issue(t, reuseClient)

	removed, err := store.RemoveExpired(context.Background(), godi.GetRequired[services.SystemClock](f.Root).Now())
	require.NoError(t, err)
	require.Zero(t, removed, "RemoveExpired reclaimed a valid refresh token")
	f.redeem(t, reuseClient, refresh)
}

func TestRefreshTokenAbsoluteExpiryAtTheTokenEndpoint(t *testing.T) {
	clock := integration_common.NewAdjustableClock(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
	f := newFixture(t, newAgingStore(clock), nil, lifetimeClients()...)
	refresh := f.issue(t, absoluteClient)

	clock.Advance(5 * time.Minute)
	f.redeem(t, absoluteClient, refresh)
	clock.Advance(4 * time.Minute) // 9 min: redemption did not extend the lifetime
	f.redeem(t, absoluteClient, refresh)
	clock.Advance(2 * time.Minute) // 11 min
	f.requireRefused(t, absoluteClient, refresh)
}

func TestRefreshTokenSlidingExpiryAtTheTokenEndpoint(t *testing.T) {
	t.Run("renewed and capped", func(t *testing.T) {
		clock := integration_common.NewAdjustableClock(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
		f := newFixture(t, newAgingStore(clock), nil, lifetimeClients()...)
		refresh := f.issue(t, slidingClient)

		clock.Advance(3 * time.Minute) // expires 4 min after this redemption
		f.redeem(t, slidingClient, refresh)
		clock.Advance(3 * time.Minute) // 6 min: past the first 4 min, still valid
		f.redeem(t, slidingClient, refresh)
		clock.Advance(3 * time.Minute) // 9 min: renewed up to the 10 min cap
		f.redeem(t, slidingClient, refresh)
		clock.Advance(2 * time.Minute) // 11 min: past the cap
		f.requireRefused(t, slidingClient, refresh)
	})
	t.Run("window lapses", func(t *testing.T) {
		clock := integration_common.NewAdjustableClock(time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC))
		f := newFixture(t, newAgingStore(clock), nil, lifetimeClients()...)
		refresh := f.issue(t, slidingClient)

		clock.Advance(3 * time.Minute)
		f.redeem(t, slidingClient, refresh)
		clock.Advance(6 * time.Minute) // 9 min: more than 4 min since the last redemption
		f.requireRefused(t, slidingClient, refresh)
	})
}
