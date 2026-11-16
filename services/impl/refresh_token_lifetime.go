// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"math"
	"time"

	"github.com/gonewx/wicket"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// unlimitedRefreshTokenLifetime is the lifetime, in seconds, recorded for a
// refresh token whose client sets no limit: about 68 years, so that the
// fixed expiry predicate of RemoveExpired never reclaims it. Every lifetime
// is kept within ±math.MaxInt32 seconds, and math.MaxInt32 seconds converted
// to a time.Duration (about 2.1e18 nanoseconds) stays below math.MaxInt64,
// so the conversion cannot overflow.
const unlimitedRefreshTokenLifetime = math.MaxInt32

// SetClock declares the clock that dates the creation, the expiry and the
// sliding extension of refresh tokens. Without it the wall clock is used;
// expiry is enforced either way. It does not declare a consumption, so a
// service given only a clock still updates refresh tokens in place. It
// panics on a nil clock.
func (s *RefreshTokenService) SetClock(clock services.SystemClock) {
	if clock == nil {
		panic("refresh token service: clock is required")
	}
	s.clock = clock
}

// now reads the declared clock, or the wall clock when none is declared.
func (s *RefreshTokenService) now() time.Time {
	if s.clock != nil {
		return s.clock.Now()
	}
	return time.Now()
}

// refreshTokenLifetime returns the lifetime, in seconds from creation, that a
// refresh token of client holds as of now. A lifetime setting of zero sets no
// limit.
//
//   - Absolute expiration: the token expires at creation + absolute.
//   - Sliding expiration with a positive sliding lifetime: the token expires at
//     now + sliding, capped at creation + absolute unless absolute is zero.
//   - Sliding expiration with a zero sliding lifetime: as absolute.
//
// When nothing limits the token, unlimitedRefreshTokenLifetime is returned.
// The time elapsed since creation is rounded up to whole seconds, so that a
// sliding extension never falls short of the sliding lifetime; the absolute
// cap still applies after rounding.
func refreshTokenLifetime(client *storage_models.Client, creation time.Time, now time.Time) int {
	absolute := clampLifetime(int64(client.AbsoluteRefreshTokenLifetime))
	sliding := clampLifetime(int64(client.SlidingRefreshTokenLifetime))
	if client.RefreshTokenExpiration == wicket.TokenExpirationSliding && sliding > 0 {
		// Both terms are bounded (the elapsed seconds by the saturation of
		// time.Time.Sub, about 9.2e9), so the sum cannot overflow int64.
		lifetime := elapsedSeconds(creation, now) + int64(sliding)
		if absolute != 0 && lifetime > int64(absolute) {
			lifetime = int64(absolute)
		}
		return clampLifetime(lifetime)
	}
	if absolute == 0 {
		return unlimitedRefreshTokenLifetime
	}
	return absolute
}

// elapsedSeconds returns now - creation in seconds, rounded up.
func elapsedSeconds(creation time.Time, now time.Time) int64 {
	elapsed := now.Sub(creation)
	seconds := int64(elapsed / time.Second)
	if elapsed%time.Second > 0 {
		seconds++
	}
	return seconds
}

// clampLifetime keeps a lifetime in seconds within ±math.MaxInt32.
func clampLifetime(seconds int64) int {
	return int(min(max(seconds, -math.MaxInt32), math.MaxInt32))
}

// refreshTokenExpired reports whether token has expired at now, by the same
// predicate RemoveExpired applies: the expiry strictly before now. The
// lifetime is clamped first so that its conversion cannot overflow.
func refreshTokenExpired(token *storage_models.RefreshToken, now time.Time) bool {
	lifetime := time.Duration(clampLifetime(int64(token.Lifetime))) * time.Second
	return token.CreationTime.Add(lifetime).Before(now)
}

// backfillRefreshTokenLifetime dates a refresh token stored without a
// creation time, as tokens issued before lifetimes were recorded are: it is
// taken as created now, with the lifetime its client grants today. The
// record is written back by the update that follows the redemption.
func backfillRefreshTokenLifetime(token *storage_models.RefreshToken, client *storage_models.Client, now time.Time) {
	if !token.CreationTime.IsZero() {
		return
	}
	token.CreationTime = now
	token.Lifetime = refreshTokenLifetime(client, now, now)
}

// extendSlidingLifetime rewrites the lifetime of the redeemed refresh token
// of a client with sliding expiration, before the update stores it in place
// or rotates it. A rotation copies the extended lifetime into both the
// successor and the consumed record, so the two expire together. Under
// absolute expiration nothing changes: rotation does not extend the lifetime.
func (s *RefreshTokenService) extendSlidingLifetime(request *responses_models.RefreshTokenUpdateRequest) {
	token, client := request.RefreshToken, request.Client
	if token == nil || client == nil ||
		client.RefreshTokenExpiration != wicket.TokenExpirationSliding || client.SlidingRefreshTokenLifetime <= 0 {
		return
	}
	now := s.now()
	backfillRefreshTokenLifetime(token, client, now)
	token.Lifetime = refreshTokenLifetime(client, token.CreationTime, now)
}
