// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt

import (
	"errors"
	"time"

	"github.com/gonewx/wicket/claims"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	errTokenIssuerMismatch   = errors.New("token issuer does not match the expected value")
	errTokenAudienceMismatch = errors.New("token audience does not contain the expected value")
)

// SecurityTokenHandler is the default SecurityTokenValidator. It delegates all
// cryptography and standard-claim validation to jwx/v2 and holds no signing key
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
	opts := make([]jwxjwt.ValidateOption, 0, 4)
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

	if parameters.ValidateLifetime {
		// jwt.Validate always runs the exp/nbf/iat validators alongside the
		// issuer/audience options and the acceptable skew assembled above.
		return jwxjwt.Validate(token, opts...)
	}

	// Lifetime validation disabled: run only the non-temporal options by
	// skipping jwt.Validate's built-in temporal validators. jwx v2.0.6 has no
	// toggle for that, so the issuer/audience checks are applied directly.
	if parameters.ValidIssuer != "" && token.Issuer() != parameters.ValidIssuer {
		return errTokenIssuerMismatch
	}
	if parameters.ValidAudience != "" && !containsString(token.Audience(), parameters.ValidAudience) {
		return errTokenAudienceMismatch
	}
	return nil
}

// principalFromToken projects the token's claims onto a ClaimsPrincipal whose
// single identity is authenticated as the JWT bearer scheme.
func principalFromToken(token jwxjwt.Token) *claims.ClaimsPrincipal {
	identity := claims.NewClaimsIdentity(
		claims.WithAuthenticationType(AuthenticationScheme),
	)
	for name, value := range token.PrivateClaims() {
		identity.AddClaim(claims.NewClaim(
			claims.WithClaimType(name),
			claims.WithClaimValue(value),
		))
	}
	addStandardClaim(identity, "iss", token.Issuer())
	// The registered "sub" claim carries the subject. Project it onto the
	// wicket-wide NameIdentifier type so downstream consumers (session,
	// userinfo, authorization gates) can locate the subject the same way they
	// do for every other scheme.
	addStandardClaim(identity, claims.NameIdentifier, token.Subject())
	addStandardClaim(identity, "jti", token.JwtID())
	for _, aud := range token.Audience() {
		addStandardClaim(identity, "aud", aud)
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

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// validatedToken adapts a validated jwx token to the SecurityToken face the
// handler reads for authentication properties.
type validatedToken struct {
	token jwxjwt.Token
}

func (t *validatedToken) ValidTo() time.Time   { return t.token.Expiration() }
func (t *validatedToken) ValidFrom() time.Time { return t.token.NotBefore() }
