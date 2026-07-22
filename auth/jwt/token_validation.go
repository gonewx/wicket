// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt

import (
	"time"

	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/services"
	"github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

// SecurityToken is a token that has passed validation. It exposes the temporal
// bounds the handler reads when populating authentication properties after a
// successful sign-in.
type SecurityToken interface {
	// ValidTo reports the instant at which the token expires. Absent claims
	// yield the zero time.
	ValidTo() time.Time
	// ValidFrom reports the instant from which the token is valid. Absent
	// claims yield the zero time.
	ValidFrom() time.Time
}

// SecurityTokenValidator reads and validates a bearer token. The handler holds
// an ordered list of validators and uses the first one that can read a given
// token.
type SecurityTokenValidator interface {
	// CanReadToken reports whether this validator recognizes the token's form.
	// It performs neither signature nor claim validation.
	CanReadToken(token string) bool

	// ValidateToken validates the token against the supplied parameters. On
	// success it returns the resulting principal and the validated token. A nil
	// principal signals that no subject could be established. A non-nil error
	// signals a validation failure; the handler moves on to the next validator.
	ValidateToken(token string, parameters *TokenValidationParameters) (*claims.ClaimsPrincipal, SecurityToken, error)
}

// TokenValidationParameters carries the standard inputs used when validating a
// bearer token. Zero-valued fields disable the corresponding check unless a
// default applies (see NewTokenValidationParameters).
type TokenValidationParameters struct {
	// ValidIssuer, when non-empty, requires the token issuer to match exactly.
	ValidIssuer string

	// ValidAudience, when non-empty, requires the token audience to contain the
	// value.
	ValidAudience string

	// Keys holds the verification key set. It is required when
	// RequireSignedTokens is true.
	Keys jwk.Set

	// RequireSignedTokens toggles signature verification.
	RequireSignedTokens bool

	// ValidateLifetime toggles the exp/nbf/iat temporal checks.
	ValidateLifetime bool

	// Clock supplies the current time for the temporal checks. When nil the
	// underlying library falls back to the system clock. Injecting a clock keeps
	// validation deterministic under test.
	Clock services.SystemClock

	// ClockSkew is the tolerance applied to the exp/nbf/iat comparisons, absorbing
	// small clock differences between the token issuer and this validator. Zero
	// disables the tolerance (exact comparison).
	ClockSkew time.Duration

	// ValidateOptions are additional jwx validate options applied alongside the
	// temporal checks.
	ValidateOptions []jwxjwt.ValidateOption
}

// DefaultClockSkew is the temporal tolerance applied when none is configured,
// matching the long-standing default of the reference implementation.
const DefaultClockSkew = 5 * time.Minute

// NewTokenValidationParameters returns parameters with safe defaults: signed
// tokens are required, the token lifetime is validated, and a small clock skew
// tolerance is applied.
func NewTokenValidationParameters() *TokenValidationParameters {
	return &TokenValidationParameters{
		RequireSignedTokens: true,
		ValidateLifetime:    true,
		ClockSkew:           DefaultClockSkew,
	}
}
