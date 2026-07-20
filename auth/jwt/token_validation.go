// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt

import (
	"time"

	"github.com/gonewx/wicket/claims"
	"github.com/gonewx/wicket/services"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
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

	// ValidateOptions are additional jwx validate options applied alongside the
	// temporal checks.
	ValidateOptions []jwxjwt.ValidateOption
}

// NewTokenValidationParameters returns parameters with safe defaults: signed
// tokens are required and the token lifetime is validated.
func NewTokenValidationParameters() *TokenValidationParameters {
	return &TokenValidationParameters{
		RequireSignedTokens: true,
		ValidateLifetime:    true,
	}
}
