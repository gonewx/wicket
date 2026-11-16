// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_impl "github.com/gonewx/wicket/storage/impl"
	"github.com/gonewx/wicket/storage/models"
)

var lifetimeStart = time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)

// lifetimeClock is a clock the test moves by hand.
type lifetimeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newLifetimeClock() *lifetimeClock { return &lifetimeClock{now: lifetimeStart} }

func (c *lifetimeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// at moves the clock to lifetimeStart + offset.
func (c *lifetimeClock) at(offset time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = lifetimeStart.Add(offset)
}

func absoluteClient(id string, absolute int) *models.Client {
	client := models.NewClient()
	client.ClientId = id
	client.RefreshTokenUsage = wicket.TokenUsageReUse
	client.RefreshTokenExpiration = wicket.TokenExpirationAbsolute
	client.AbsoluteRefreshTokenLifetime = absolute
	return client
}

func slidingClient(id string, sliding int, absolute int) *models.Client {
	client := absoluteClient(id, absolute)
	client.RefreshTokenExpiration = wicket.TokenExpirationSliding
	client.SlidingRefreshTokenLifetime = sliding
	return client
}

func lifetimeService(store storage.RefreshTokenStore, clock services.SystemClock) *RefreshTokenService {
	service := NewRefreshTokenService(store, NewHandleGenerationService())
	service.SetClock(clock)
	return service
}

func createRefreshToken(t *testing.T, service *RefreshTokenService, client *models.Client) string {
	t.Helper()
	handle, err := service.CreateRefreshToken(context.Background(), &responses_models.RefreshTokenCreationRequest{Client: client})
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	return handle
}

func storedRefreshToken(t *testing.T, store storage.RefreshTokenStore, handle string) *models.RefreshToken {
	t.Helper()
	token, err := store.GetRefreshToken(context.Background(), handle)
	if err != nil {
		t.Fatalf("get refresh token: %v", err)
	}
	return token
}

// redeemRefreshToken validates and updates the refresh token the way the
// token endpoint does and returns the handle of the response.
func redeemRefreshToken(t *testing.T, service *RefreshTokenService, handle string, client *models.Client) string {
	t.Helper()
	result := service.ValidateRefreshToken(context.Background(), handle, client)
	if result.Error != nil {
		t.Fatalf("validate refresh token: %v", result.Error)
	}
	next, err := service.UpdateRefreshToken(context.Background(), &responses_models.RefreshTokenUpdateRequest{
		Handle:       handle,
		Client:       client,
		RefreshToken: result.RefreshToken,
		AccessToken:  &models.Token{},
	})
	if err != nil {
		t.Fatalf("update refresh token: %v", err)
	}
	return next
}

func requireExpired(t *testing.T, service *RefreshTokenService, handle string, client *models.Client) {
	t.Helper()
	result := service.ValidateRefreshToken(context.Background(), handle, client)
	if !errors.Is(result.Error, storage.ErrNotFound) {
		t.Fatalf("validate refresh token: error = %v, want one wrapping storage.ErrNotFound", result.Error)
	}
	if result.RefreshToken != nil {
		t.Fatal("an expired refresh token is returned")
	}
	if strings.Contains(result.Error.Error(), handle) {
		t.Fatalf("error %q contains the handle", result.Error)
	}
}

func TestRefreshTokenLifetimeRecordedOnIssue(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		client   *models.Client
		lifetime int
	}{
		"default client":             {client: func() *models.Client { c := models.NewClient(); c.ClientId = "c"; return c }(), lifetime: 2592000},
		"absolute":                   {client: absoluteClient("c", 600), lifetime: 600},
		"absolute unlimited":         {client: absoluteClient("c", 0), lifetime: math.MaxInt32},
		"sliding":                    {client: slidingClient("c", 4, 10), lifetime: 4},
		"sliding without cap":        {client: slidingClient("c", 4, 0), lifetime: 4},
		"sliding above the cap":      {client: slidingClient("c", 20, 10), lifetime: 10},
		"sliding zero as absolute":   {client: slidingClient("c", 0, 10), lifetime: 10},
		"sliding zero and unlimited": {client: slidingClient("c", 0, 0), lifetime: math.MaxInt32},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := storage_impl.NewRefreshTokenStore()
			service := lifetimeService(store, newLifetimeClock())
			token := storedRefreshToken(t, store, createRefreshToken(t, service, tc.client))
			if !token.CreationTime.Equal(lifetimeStart) {
				t.Fatalf("CreationTime = %v, want %v", token.CreationTime, lifetimeStart)
			}
			if token.Lifetime != tc.lifetime {
				t.Fatalf("Lifetime = %d, want %d", token.Lifetime, tc.lifetime)
			}
		})
	}
}

// AC1: a refresh token issued by a service on the wall clock, as the default
// assembly is, survives RemoveExpired(now) and is redeemed afterwards.
func TestRefreshTokenSurvivesRemoveExpired(t *testing.T) {
	t.Parallel()
	cases := map[string]*models.Client{
		"default client": func() *models.Client { c := models.NewClient(); c.ClientId = "c"; return c }(),
		"unlimited":      absoluteClient("c", 0),
		"sliding":        slidingClient("c", 60, 0),
	}
	for name, client := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := storage_impl.NewRefreshTokenStore()
			service := NewRefreshTokenService(store, NewHandleGenerationService())
			handle := createRefreshToken(t, service, client)

			removed, err := store.RemoveExpired(context.Background(), NewSystemClock().Now())
			if err != nil {
				t.Fatalf("remove expired: %v", err)
			}
			if removed != 0 {
				t.Fatalf("RemoveExpired removed %d refresh tokens, want 0", removed)
			}
			redeemRefreshToken(t, service, handle, client)
		})
	}
}

// An unlimited refresh token is not reclaimed decades later.
func TestRefreshTokenUnlimitedSurvivesRemoveExpired(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := lifetimeService(store, clock)
	client := absoluteClient("c", 0)
	handle := createRefreshToken(t, service, client)

	later := 60 * 365 * 24 * time.Hour
	removed, err := store.RemoveExpired(context.Background(), lifetimeStart.Add(later))
	if err != nil || removed != 0 {
		t.Fatalf("RemoveExpired = %d, %v; want 0, nil", removed, err)
	}
	clock.at(later)
	redeemRefreshToken(t, service, handle, client)
}

func TestRefreshTokenAbsoluteExpiry(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := lifetimeService(store, clock)
	client := absoluteClient("c", 10)
	handle := createRefreshToken(t, service, client)

	clock.at(5 * time.Second)
	redeemRefreshToken(t, service, handle, client)
	if token := storedRefreshToken(t, store, handle); token.Lifetime != 10 || !token.CreationTime.Equal(lifetimeStart) {
		t.Fatalf("redemption changed the absolute lifetime: %v + %ds", token.CreationTime, token.Lifetime)
	}
	// The expiry itself is not past, as for RemoveExpired.
	clock.at(10 * time.Second)
	redeemRefreshToken(t, service, handle, client)
	if removed, _ := store.RemoveExpired(context.Background(), clock.Now()); removed != 0 {
		t.Fatalf("RemoveExpired at the expiry removed %d", removed)
	}

	clock.at(10*time.Second + time.Nanosecond)
	requireExpired(t, service, handle, client)
	// Expiry does not remove the record: reclaiming it is the host's.
	storedRefreshToken(t, store, handle)
	if removed, _ := store.RemoveExpired(context.Background(), clock.Now()); removed != 1 {
		t.Fatalf("RemoveExpired after the expiry removed %d, want 1", removed)
	}
}

func TestRefreshTokenSlidingExpiry(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := lifetimeService(store, clock)
	client := slidingClient("c", 4, 10)
	handle := createRefreshToken(t, service, client)

	steps := []struct {
		at       time.Duration
		lifetime int
	}{
		{3 * time.Second, 7},  // expires at 7s
		{6 * time.Second, 10}, // now + 4 = 10s, the cap
		{9 * time.Second, 10}, // now + 4 = 13s, capped at 10s
		{10 * time.Second, 10},
	}
	for _, step := range steps {
		clock.at(step.at)
		if next := redeemRefreshToken(t, service, handle, client); next != handle {
			t.Fatalf("handle changed at %v", step.at)
		}
		token := storedRefreshToken(t, store, handle)
		if token.Lifetime != step.lifetime || !token.CreationTime.Equal(lifetimeStart) {
			t.Fatalf("at %v: stored %v + %ds, want %v + %ds", step.at, token.CreationTime, token.Lifetime, lifetimeStart, step.lifetime)
		}
	}
	clock.at(11 * time.Second)
	requireExpired(t, service, handle, client)
}

// A redemption after the sliding window has passed is refused even though
// the absolute lifetime has not.
func TestRefreshTokenSlidingWindowLapses(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := lifetimeService(store, clock)
	client := slidingClient("c", 4, 10)
	handle := createRefreshToken(t, service, client)

	clock.at(3 * time.Second)
	redeemRefreshToken(t, service, handle, client)
	clock.at(7*time.Second + time.Nanosecond)
	requireExpired(t, service, handle, client)
}

// The elapsed time is rounded up to whole seconds, so the extension never
// falls short of the sliding lifetime, and the cap still holds.
func TestRefreshTokenSlidingRoundsUp(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := lifetimeService(store, clock)
	client := slidingClient("c", 4, 10)
	handle := createRefreshToken(t, service, client)

	clock.at(2500 * time.Millisecond)
	redeemRefreshToken(t, service, handle, client)
	if lifetime := storedRefreshToken(t, store, handle).Lifetime; lifetime != 7 {
		t.Fatalf("Lifetime = %d, want 7", lifetime)
	}
	clock.at(6500 * time.Millisecond)
	redeemRefreshToken(t, service, handle, client)
	if lifetime := storedRefreshToken(t, store, handle).Lifetime; lifetime != 10 {
		t.Fatalf("Lifetime = %d, want the cap 10", lifetime)
	}
}

// Under a marking consumption the successor and the consumed record carry
// the extended lifetime of a sliding client and expire together; under
// absolute expiration both inherit the creation time and lifetime.
func TestRefreshTokenLifetimeOnRotation(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		client   *models.Client
		lifetime int
	}{
		"sliding":  {client: slidingClient("c", 4, 10), lifetime: 7},
		"absolute": {client: absoluteClient("c", 10), lifetime: 10},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.client.RefreshTokenUsage = wicket.TokenUsageOneTimeOnly
			store := storage_impl.NewRefreshTokenStore()
			clock := newLifetimeClock()
			service := NewRefreshTokenService(store, NewHandleGenerationService())
			service.SetConsumption(services.RefreshTokenMarkedOnRedemption, clock, nil)
			handle := createRefreshToken(t, service, tc.client)

			clock.at(3 * time.Second)
			successor := redeemRefreshToken(t, service, handle, tc.client)
			if successor == handle {
				t.Fatal("the refresh token was not rotated")
			}
			for role, h := range map[string]string{"consumed": handle, "successor": successor} {
				token := storedRefreshToken(t, store, h)
				if token.Lifetime != tc.lifetime || !token.CreationTime.Equal(lifetimeStart) {
					t.Fatalf("%s record: %v + %ds, want %v + %ds", role, token.CreationTime, token.Lifetime, lifetimeStart, tc.lifetime)
				}
			}
			if storedRefreshToken(t, store, handle).ConsumedTime == nil {
				t.Fatal("the redeemed record is not consumed")
			}
		})
	}
}

// A record stored without a creation time is dated on its first redemption
// with the lifetime its client grants, and written back.
func TestRefreshTokenLegacyRecordBackfilled(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		client   *models.Client
		lifetime int
	}{
		"absolute":  {client: absoluteClient("c", 600), lifetime: 600},
		"unlimited": {client: absoluteClient("c", 0), lifetime: math.MaxInt32},
		"sliding":   {client: slidingClient("c", 4, 10), lifetime: 4},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := storage_impl.NewRefreshTokenStore()
			clock := newLifetimeClock()
			service := lifetimeService(store, clock)
			legacy := models.NewRefreshToken()
			legacy.ClientId = tc.client.ClientId
			if err := store.StoreRefreshToken(context.Background(), "legacy", legacy); err != nil {
				t.Fatal(err)
			}

			clock.at(time.Hour)
			if next := redeemRefreshToken(t, service, "legacy", tc.client); next != "legacy" {
				t.Fatal("handle changed")
			}
			token := storedRefreshToken(t, store, "legacy")
			if !token.CreationTime.Equal(lifetimeStart.Add(time.Hour)) || token.Lifetime != tc.lifetime {
				t.Fatalf("written back %v + %ds, want %v + %ds", token.CreationTime, token.Lifetime, lifetimeStart.Add(time.Hour), tc.lifetime)
			}
		})
	}
}

// A consumed refresh token presented again by its client is answered as a
// replay even once it has expired: the tokens down its link are revoked.
func TestRefreshTokenExpiredReplayStillRevokes(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := NewRefreshTokenService(store, NewHandleGenerationService())
	service.SetConsumption(services.RefreshTokenMarkedOnRedemption, clock, nil)
	client := absoluteClient("c", 10)
	client.RefreshTokenUsage = wicket.TokenUsageOneTimeOnly
	handle := createRefreshToken(t, service, client)
	clock.at(time.Second)
	successor := redeemRefreshToken(t, service, handle, client)

	clock.at(time.Minute)
	result := service.ValidateRefreshToken(context.Background(), handle, client)
	if !errors.Is(result.Error, storage.ErrNotFound) || !strings.Contains(result.Error.Error(), "already consumed") {
		t.Fatalf("replay: error = %v, want the consumed refusal", result.Error)
	}
	if storedRefreshToken(t, store, successor).ConsumedTime == nil {
		t.Fatal("the successor of the replayed token is not revoked")
	}
}

// Under sliding expiration a consumed record can expire while the latest
// token down its link is still valid; replaying the expired record still
// revokes that token.
func TestRefreshTokenExpiredSlidingReplayRevokesLiveSuccessor(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := NewRefreshTokenService(store, NewHandleGenerationService())
	service.SetConsumption(services.RefreshTokenMarkedOnRedemption, clock, nil)
	client := slidingClient("c", 4, 100)
	client.RefreshTokenUsage = wicket.TokenUsageOneTimeOnly
	first := createRefreshToken(t, service, client)

	clock.at(3 * time.Second) // first consumed, expires at 7s
	second := redeemRefreshToken(t, service, first, client)
	clock.at(6 * time.Second) // second consumed; latest expires at 10s
	latest := redeemRefreshToken(t, service, second, client)

	clock.at(8 * time.Second)
	if expired := storedRefreshToken(t, store, first); !refreshTokenExpired(expired, clock.Now()) {
		t.Fatalf("the first record should have expired: %v + %ds", expired.CreationTime, expired.Lifetime)
	}
	if live := storedRefreshToken(t, store, latest); refreshTokenExpired(live, clock.Now()) || live.ConsumedTime != nil {
		t.Fatal("the latest token should still be valid before the replay")
	}
	result := service.ValidateRefreshToken(context.Background(), first, client)
	if !errors.Is(result.Error, storage.ErrNotFound) || !strings.Contains(result.Error.Error(), "already consumed") {
		t.Fatalf("replay: error = %v, want the consumed refusal", result.Error)
	}
	if storedRefreshToken(t, store, latest).ConsumedTime == nil {
		t.Fatal("the latest token down the link of the expired replayed record is not revoked")
	}
}

// Another client presenting an expired refresh token gets the answer it gets
// for any token of another client, which does not tell it the token expired.
func TestRefreshTokenExpiryHiddenFromAnotherClient(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	clock := newLifetimeClock()
	service := lifetimeService(store, clock)
	client := absoluteClient("c", 10)
	handle := createRefreshToken(t, service, client)

	clock.at(time.Minute)
	result := service.ValidateRefreshToken(context.Background(), handle, absoluteClient("other", 10))
	if !errors.Is(result.Error, storage.ErrNotFound) || !strings.Contains(result.Error.Error(), "another client") {
		t.Fatalf("error = %v, want the refusal for another client", result.Error)
	}
	requireExpired(t, service, handle, client)
}

// AC3: a clock alone does not make the service rotate.
func TestRefreshTokenClockDoesNotRotate(t *testing.T) {
	t.Parallel()
	store := storage_impl.NewRefreshTokenStore()
	service := lifetimeService(store, newLifetimeClock())
	client := absoluteClient("c", 600)
	client.RefreshTokenUsage = wicket.TokenUsageOneTimeOnly
	handle := createRefreshToken(t, service, client)
	if next := redeemRefreshToken(t, service, handle, client); next != handle {
		t.Fatal("a service given only a clock rotated the refresh token")
	}
}

func TestRefreshTokenSetClockRefusesNil(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("SetClock(nil) did not panic")
		}
	}()
	NewRefreshTokenService(storage_impl.NewRefreshTokenStore(), NewHandleGenerationService()).SetClock(nil)
}

func TestRefreshTokenLifetimeDoesNotOverflow(t *testing.T) {
	t.Parallel()
	now := lifetimeStart
	cases := map[string]struct {
		client   *models.Client
		creation time.Time
		lifetime int
	}{
		"huge absolute":                 {client: absoluteClient("c", math.MaxInt), creation: now, lifetime: math.MaxInt32},
		"huge sliding":                  {client: slidingClient("c", math.MaxInt, 0), creation: now, lifetime: math.MaxInt32},
		"huge sliding capped":           {client: slidingClient("c", math.MaxInt, 10), creation: now, lifetime: 10},
		"creation at the zero time":     {client: slidingClient("c", 4, 0), creation: time.Time{}, lifetime: math.MaxInt32},
		"creation far in the future":    {client: slidingClient("c", 4, 0), creation: now.Add(1 << 62), lifetime: -math.MaxInt32},
		"negative absolute stays short": {client: absoluteClient("c", math.MinInt), creation: now, lifetime: -math.MaxInt32},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := refreshTokenLifetime(tc.client, tc.creation, now); got != tc.lifetime {
				t.Fatalf("lifetime = %d, want %d", got, tc.lifetime)
			}
		})
	}

	expired := map[string]struct {
		lifetime int
		want     bool
	}{
		"largest int":  {lifetime: math.MaxInt, want: false},
		"smallest int": {lifetime: math.MinInt, want: true},
		"unlimited":    {lifetime: math.MaxInt32, want: false},
	}
	for name, tc := range expired {
		t.Run("expired "+name, func(t *testing.T) {
			t.Parallel()
			token := models.NewRefreshToken()
			token.CreationTime = now
			token.Lifetime = tc.lifetime
			if got := refreshTokenExpired(token, now.Add(time.Hour)); got != tc.want {
				t.Fatalf("expired = %v, want %v", got, tc.want)
			}
		})
	}
	// MaxInt32 seconds converts to a positive duration.
	if d := time.Duration(math.MaxInt32) * time.Second; d <= 0 {
		t.Fatalf("MaxInt32 seconds overflow to %v", d)
	}
}
