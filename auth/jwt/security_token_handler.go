// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt

import (
	"time"

	"github.com/gonewx/wicket/claims"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"
)

// SecurityTokenHandler is the default SecurityTokenValidator. It delegates all
// cryptography and standard-claim validation to jwx/v3 and holds no signing key
// material of its own.
type SecurityTokenHandler struct{}

// NewSecurityTokenHandler returns the default jwx-backed validator.
func NewSecurityTokenHandler() *SecurityTokenHandler {
	return &SecurityTokenHandler{}
}

var _ SecurityTokenValidator = (*SecurityTokenHandler)(nil)

// CanReadToken reports whether the value parses as a JWT. It performs neither
// signature nor claim validation.
func (h *SecurityTokenHandler) CanReadToken(token string) bool {
	_, err := jwxjwt.ParseInsecure([]byte(token))
	return err == nil
}

// ValidateToken verifies the token signature and standard claims against the
// supplied parameters, then projects the token claims onto a ClaimsPrincipal.
func (h *SecurityTokenHandler) ValidateToken(
	token string,
	parameters *TokenValidationParameters,
) (*claims.ClaimsPrincipal, SecurityToken, error) {
	if parameters == nil {
		parameters = NewTokenValidationParameters()
	}

	parseOpts := make([]jwxjwt.ParseOption, 0, 4)
	if parameters.RequireSignedTokens {
		if parameters.Keys != nil {
			parseOpts = append(parseOpts, jwxjwt.WithKeySet(parameters.Keys))
		}
	} else {
		parseOpts = append(parseOpts, jwxjwt.WithVerify(false))
	}
	// Claim validation is driven explicitly below so the lifetime toggle is
	// honored; keep it off during the parse itself.
	parseOpts = append(parseOpts, jwxjwt.WithValidate(false))

	parsed, err := jwxjwt.Parse([]byte(token), parseOpts...)
	if err != nil {
		return nil, nil, err
	}

	if err := h.validateClaims(parsed, parameters); err != nil {
		return nil, nil, err
	}

	principal := principalFromToken(parsed)
	return principal, &validatedToken{token: parsed}, nil
}

// validateClaims applies issuer/audience checks always and the exp/nbf/iat
// checks only when the lifetime toggle is set. All checks delegate to jwx.
func (h *SecurityTokenHandler) validateClaims(
	token jwxjwt.Token,
	parameters *TokenValidationParameters,
) error {
	opts := make([]jwxjwt.ValidateOption, 0, 5)
	if parameters.Clock != nil {
		opts = append(opts, jwxjwt.WithClock(parameters.Clock))
	}
	if parameters.ValidIssuer != "" {
		opts = append(opts, jwxjwt.WithIssuer(parameters.ValidIssuer))
	}
	if parameters.ValidAudience != "" {
		opts = append(opts, jwxjwt.WithAudience(parameters.ValidAudience))
	}
	if parameters.ClockSkew > 0 {
		opts = append(opts, jwxjwt.WithAcceptableSkew(parameters.ClockSkew))
	}
	opts = append(opts, parameters.ValidateOptions...)
	opts = append(opts, jwxjwt.WithTruncation(time.Second))

	if parameters.ValidateLifetime {
		return jwxjwt.Validate(token, opts...)
	}

	// Lifetime validation disabled: reset the default temporal validators
	// (exp/nbf/iat) while retaining issuer/audience/clock/skew constraints.
	opts = append(opts, jwxjwt.WithResetValidators(true))
	return jwxjwt.Validate(token, opts...)
}

// principalFromToken projects the token's claims onto a ClaimsPrincipal whose
// single identity is authenticated as the JWT bearer scheme.
func principalFromToken(token jwxjwt.Token) *claims.ClaimsPrincipal {
	identity := claims.NewClaimsIdentity(
		claims.WithAuthenticationType(AuthenticationScheme),
	)
	for _, name := range token.Keys() {
		switch name {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
			continue
		}
		var value any
		if err := token.Get(name, &value); err != nil {
			continue
		}
		identity.AddClaim(claims.NewClaim(
			claims.WithClaimType(name),
			claims.WithClaimValue(value),
		))
	}
	iss, _ := token.Issuer()
	addStandardClaim(identity, "iss", iss)
	sub, _ := token.Subject()
	addStandardClaim(identity, claims.NameIdentifier, sub)
	jti, _ := token.JwtID()
	addStandardClaim(identity, "jti", jti)
	aud, _ := token.Audience()
	for _, a := range aud {
		addStandardClaim(identity, "aud", a)
	}
	return claims.NewClaimsPrincipal(claims.WithClaimsPrincipalIdentity(identity))
}

func addStandardClaim(identity *claims.ClaimsIdentity, name, value string) {
	if value == "" {
		return
	}
	identity.AddClaim(claims.NewClaim(
		claims.WithClaimType(name),
		claims.WithClaimValue(value),
	))
}

// validatedToken adapts a validated jwx token to the SecurityToken face the
// handler reads for authentication properties.
type validatedToken struct {
	token jwxjwt.Token
}

func (t *validatedToken) ValidTo() time.Time   { exp, _ := t.token.Expiration(); return exp }
func (t *validatedToken) ValidFrom() time.Time { nbf, _ := t.token.NotBefore(); return nbf }
