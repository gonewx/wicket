// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gonewx/wicket/replay"
)

var (
	// ErrReplayedProof reports a proof whose identifier was already
	// registered for the same key. It wraps replay.ErrDuplicateHandle.
	ErrReplayedProof = errors.New("dpop: proof replayed")
	// ErrRegistrationUnavailable reports that the proof identifier could not
	// be registered. Nothing may be concluded from it: it is neither a replay
	// nor an accepted proof.
	ErrRegistrationUnavailable = errors.New("dpop: proof registration unavailable")
)

// RegistrationExpiry returns the instant the registry record of proof may be
// reclaimed: the later of the last instant the proof is accepted (iat plus
// the proof lifetime) and now, plus the clock skew.
func RegistrationExpiry(proof Proof, options Options, now time.Time) time.Time {
	options = options.withDefaults()
	until := proof.IssuedAt.Add(options.ProofLifetime)
	if now.After(until) {
		until = now
	}
	return until.Add(options.ClockSkew)
}

// Register records the identifier of an accepted proof. The key is derived
// with replay.Key from the DPoP proof purpose, the proof key thumbprint and
// the jti. A key already registered yields ErrReplayedProof wrapping
// replay.ErrDuplicateHandle; any other failure, a failure to derive the key
// included, yields ErrRegistrationUnavailable wrapping the cause. The text of
// a wrapped cause may carry the key and must not be logged.
func Register(ctx context.Context, registry replay.Registry, proof Proof, options Options, now time.Time) error {
	if registry == nil {
		return fmt.Errorf("%w: no registry", ErrRegistrationUnavailable)
	}
	key, err := replay.Key(replay.PurposeDPoPProof(), proof.Thumbprint, proof.JwtId)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRegistrationUnavailable, err)
	}
	err = registry.Register(ctx, key, RegistrationExpiry(proof, options, now))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, replay.ErrDuplicateHandle):
		return fmt.Errorf("%w: %w", ErrReplayedProof, err)
	default:
		return fmt.Errorf("%w: %w", ErrRegistrationUnavailable, err)
	}
}
