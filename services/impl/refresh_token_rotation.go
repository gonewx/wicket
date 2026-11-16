// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package impl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/dpop"
	responses_models "github.com/gonewx/wicket/responses/models"
	"github.com/gonewx/wicket/services"
	"github.com/gonewx/wicket/storage"
	storage_models "github.com/gonewx/wicket/storage/models"
)

// maxConflictRereads bounds how often the revocation walk re-reads one
// handle after losing its versioned write. Each loss means a concurrent
// redemption or revocation moved that record on, which settles within a few
// rounds; a store that keeps reporting conflicts on one handle is faulty, and
// the walk fails rather than report a revocation it did not make.
const maxConflictRereads = 8

// SetConsumption declares what happens to a one-time refresh token once it
// has been redeemed, together with the clock that stamps the consumption and
// an optional logger for cleanup failures. The clock is also used to revoke
// the successors of a replayed token, whatever the consumption. It panics on
// an undeclared consumption or a nil clock.
func (s *RefreshTokenService) SetConsumption(consumption services.RefreshTokenConsumption, clock services.SystemClock, logger *slog.Logger) {
	if !consumption.Valid() {
		panic(fmt.Sprintf("refresh token consumption: undeclared value %d", int(consumption)))
	}
	if clock == nil {
		panic("refresh token consumption: clock is required")
	}
	s.consumption = consumption
	s.clock = clock
	s.logger = logger
}

// rotates reports whether the redemption described by request issues a new
// handle: only a one-time refresh token does, and only while a consumption
// that rotates is declared.
func (s *RefreshTokenService) rotates(request *responses_models.RefreshTokenUpdateRequest) bool {
	return s.consumption.Rotates() &&
		s.clock != nil &&
		request.RefreshToken != nil &&
		request.Client != nil &&
		request.Client.RefreshTokenUsage == wicket.TokenUsageOneTimeOnly
}

// rotate stores the successor first and consumes the redeemed record second,
// under the version the redemption read. A store failure therefore leaves the
// redeemed token untouched, and of concurrent redemptions exactly one
// consumes it; every other one removes the successor it stored and fails
// with storage.ErrVersionConflict.
func (s *RefreshTokenService) rotate(ctx context.Context, request *responses_models.RefreshTokenUpdateRequest) (string, error) {
	redeemed := request.RefreshToken
	expected := redeemed.Version
	if request.AccessToken != nil {
		redeemed.SetAccessToken(request.AccessToken, request.RequestedResourceGap)
	}

	handle, err := s.handles.Generate()
	if err != nil {
		return "", fmt.Errorf("rotate refresh token: generate handle: %w", err)
	}
	if err := s.store.StoreRefreshToken(ctx, handle, successorOf(redeemed)); err != nil {
		return "", fmt.Errorf("rotate refresh token: store successor: %w", err)
	}

	consumed := *redeemed
	now := s.clock.Now()
	consumed.ConsumedTime = &now
	consumed.RotatedTo = ""
	if s.consumption == services.RefreshTokenMarkedOnRedemption {
		consumed.RotatedTo = handle
	}
	if err := s.store.UpdateRefreshToken(ctx, request.Handle, &consumed, expected); err != nil {
		if !errors.Is(err, storage.ErrVersionConflict) && !errors.Is(err, storage.ErrNotFound) &&
			s.consumedInto(ctx, request.Handle, consumed.RotatedTo) {
			// The store reported a failure for a write it applied: the
			// redeemed token now links to the successor, so the successor
			// is the client's only valid token and is answered.
			if s.logger != nil {
				s.logger.Warn("Refresh token store reported a failure for a consumption it applied; answering the successor",
					slog.String("errorType", fmt.Sprintf("%T", err)),
				)
			}
			return handle, nil
		}
		s.removeQuietly(ctx, handle, "successor")
		// A concurrent redemption that removed the record has consumed it
		// as surely as one that updated it.
		if errors.Is(err, storage.ErrVersionConflict) || errors.Is(err, storage.ErrNotFound) {
			return "", fmt.Errorf("rotate refresh token: already redeemed: %w", storage.ErrVersionConflict)
		}
		return "", fmt.Errorf("rotate refresh token: consume redeemed token: %w", err)
	}
	if s.consumption == services.RefreshTokenRemovedOnRedemption {
		// A failure leaves a record marked as consumed, which is refused
		// all the same.
		s.removeQuietly(ctx, request.Handle, "redeemed")
	}
	return handle, nil
}

// consumedInto reports whether the record under handle is consumed with a
// link to successor, which only the redemption that stored successor writes.
// Only a marking consumption writes the link; under a removing one the
// record cannot be told apart from one consumed by a concurrent redemption,
// so it reports false.
func (s *RefreshTokenService) consumedInto(ctx context.Context, handle string, successor string) bool {
	if successor == "" {
		return false
	}
	token, err := s.store.GetRefreshToken(ctx, handle)
	return err == nil && token.ConsumedTime != nil && token.RotatedTo == successor
}

// successorOf returns the record stored under a new handle: everything the
// redeemed token authorizes, its creation time and lifetime and its proof
// binding, but neither the consumption, the link nor the version. Under
// absolute expiration rotation does not extend the lifetime; under sliding
// expiration the redeemed token already carries the extended lifetime (see
// extendSlidingLifetime), which the successor and the consumed record share.
func successorOf(redeemed *storage_models.RefreshToken) *storage_models.RefreshToken {
	successor := *redeemed
	successor.AccessTokens = maps.Clone(redeemed.AccessTokens)
	if successor.AccessTokens == nil {
		successor.AccessTokens = map[string]*storage_models.Token{}
	}
	successor.AuthorizedScopes = slices.Clone(redeemed.AuthorizedScopes)
	successor.AuthorizedResourceGaps = slices.Clone(redeemed.AuthorizedResourceGaps)
	successor.ConsumedTime = nil
	successor.RotatedTo = ""
	successor.Version = 0
	return &successor
}

// refuseConsumed answers the presentation of a consumed refresh token. When
// the client it was issued to presents it, the token is taken as replayed and
// the refresh tokens still valid down its link are revoked first. A token
// bound to a DPoP key revokes only when presented with a proof of that key:
// whoever holds the token without the key cannot revoke the chain of the
// client holding it. The result wraps storage.ErrNotFound, so the token
// endpoint answers invalid_grant, unless the revocation failed on the store:
// that error does not wrap it. Once revoked, the replayed token is unlinked,
// so presenting it again is refused without a second walk.
func (s *RefreshTokenService) refuseConsumed(ctx context.Context, handle string, token *storage_models.RefreshToken, client *storage_models.Client) error {
	if client != nil && client.ClientId == token.ClientId && token.RotatedTo != "" && s.clock != nil &&
		(token.DPoPKeyThumbprint == "" || dpop.ProofThumbprint(ctx) == token.DPoPKeyThumbprint) {
		if err := s.revokeFrom(ctx, handle, token.RotatedTo); err != nil {
			return fmt.Errorf("revoke refresh tokens issued after a replayed one: %w", err)
		}
		if s.logger != nil {
			attributes := []any{slog.String("clientId", token.ClientId)}
			if token.SessionId != "" {
				attributes = append(attributes, slog.String("sessionId", token.SessionId))
			}
			s.logger.Warn("Consumed refresh token presented again by its client; the refresh tokens issued after it are revoked", attributes...)
		}
		s.unlinkReplayed(ctx, handle, token)
	}
	return fmt.Errorf("refresh token already consumed: %w", storage.ErrNotFound)
}

// unlinkReplayed drops the link of a replayed token once the tokens down it
// are revoked, so that presenting it again is refused without walking the
// chain a second time. The link is only a shortcut at this point: a failed
// write is logged, a lost race (another replay unlinked or removed it) is not.
func (s *RefreshTokenService) unlinkReplayed(ctx context.Context, handle string, token *storage_models.RefreshToken) {
	unlinked := *token
	unlinked.RotatedTo = ""
	err := s.store.UpdateRefreshToken(ctx, handle, &unlinked, token.Version)
	if err == nil || errors.Is(err, storage.ErrVersionConflict) || errors.Is(err, storage.ErrNotFound) {
		return
	}
	if s.logger != nil {
		s.logger.Warn("Replayed refresh token could not be unlinked after revocation",
			slog.String("errorType", fmt.Sprintf("%T", err)),
		)
	}
}

// revokeFrom walks the link from the replayed token (under replayed) starting
// at handle and marks the first refresh token still valid as consumed,
// without a successor. Marking rather than removing goes through the version
// check, so a redemption racing the revocation either loses or is seen and
// walked past. A missing record ends the walk; any other store error is
// returned as is, never as a missing record.
func (s *RefreshTokenService) revokeFrom(ctx context.Context, replayed string, handle string) error {
	// The walk has no length limit, since a legitimate chain grows by one
	// link per redemption for the whole lifetime of the token. Only a cycle,
	// which a faulty store could hold, would make it endless; every record
	// on a cycle is consumed, so reaching a handle walked past again leaves
	// nothing to revoke.
	walked := map[string]struct{}{replayed: {}}
	conflicts := 0
	for handle != "" {
		if _, seen := walked[handle]; seen {
			if s.logger != nil {
				s.logger.Warn("Refresh token revocation stopped at a cycle in the rotation links")
			}
			return nil
		}
		token, err := s.store.GetRefreshToken(ctx, handle)
		if errors.Is(err, storage.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if token.ConsumedTime != nil {
			walked[handle] = struct{}{}
			handle = token.RotatedTo
			conflicts = 0
			continue
		}
		now := s.clock.Now()
		token.ConsumedTime = &now
		token.RotatedTo = ""
		err = s.store.UpdateRefreshToken(ctx, handle, token, token.Version)
		switch {
		case err == nil, errors.Is(err, storage.ErrNotFound):
			return nil
		case errors.Is(err, storage.ErrVersionConflict):
			// Redeemed or revoked meanwhile: read the same handle again.
			conflicts++
			if conflicts >= maxConflictRereads {
				return fmt.Errorf("refresh token store kept reporting version conflicts after %d attempts", conflicts)
			}
			continue
		default:
			return err
		}
	}
	return nil
}

// removeQuietly removes the refresh token stored under handle; a failure is
// only logged, without the handle.
func (s *RefreshTokenService) removeQuietly(ctx context.Context, handle string, role string) {
	if err := s.store.RemoveRefreshToken(ctx, handle); err != nil && s.logger != nil {
		s.logger.Warn("Refresh token could not be removed after rotation",
			slog.String("token", role),
			slog.String("errorType", fmt.Sprintf("%T", err)),
		)
	}
}
