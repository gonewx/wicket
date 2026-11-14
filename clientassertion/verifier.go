// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientassertion

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/gonewx/wicket/replay"
	"github.com/gonewx/wicket/services"
)

// Verifier checks one client assertion and records its identifier.
type Verifier struct {
	options  func() Options
	keys     *KeySource
	registry replay.Registry
	clock    services.SystemClock
	logger   *slog.Logger
}

// NewVerifier returns a verifier. options is read on every use, so a
// verifier built before the feature is configured sees the final options.
// The registry is only called for an assertion that passed every stateless
// check.
func NewVerifier(options func() Options, keys *KeySource, registry replay.Registry, clock services.SystemClock, logger *slog.Logger) *Verifier {
	return &Verifier{options: options, keys: keys, registry: registry, clock: clock, logger: logger}
}

// assertionHeader holds the protected header members that take part in the
// decision. Key material carried in the header (jwk, jku, x5u, x5c) is never
// read, and typ is not judged.
type assertionHeader struct {
	Algorithm string          `json:"alg"`
	KeyId     *string         `json:"kid"`
	Critical  json.RawMessage `json:"crit"`
}

// Verify decides whether assertion authenticates principal towards the
// authorization server identified by audience. The stages run in a fixed
// order and the first failure ends the call: structure, header and
// algorithm, public key, signature, claims, and last the registration of
// the assertion identifier.
//
// A nil result means the assertion is valid and was used for the first time.
// ErrAuthenticationUnavailable means the replay registry failed; nothing may
// be concluded from it. Any other error is a validation failure, a replayed
// assertion included; callers must not tell these apart towards the client.
func (v *Verifier) Verify(ctx context.Context, principal Principal, audience string, assertion string) error {
	options := currentOptions(v.options)
	header, expiresAt, identifier, err := v.checkStateless(ctx, options, principal, audience, assertion)
	if err != nil {
		v.logRejection(principal, header, rejectionReason(err))
		return err
	}

	now := v.clock.Now()
	recordUntil := expiresAt
	if now.After(recordUntil) {
		recordUntil = now
	}
	recordUntil = recordUntil.Add(options.ClockSkew)

	key, err := replay.Key(replay.PurposeClientAssertion(), principal.ID, identifier)
	if err == nil {
		err = v.registry.Register(ctx, key, recordUntil)
	}
	switch {
	case err == nil:
		return nil
	case errors.Is(err, replay.ErrDuplicateHandle):
		v.logRejection(principal, header, reasonReplay)
		return reject(reasonReplay)
	default:
		// The text of the underlying error may carry the registry key, so
		// only its type is recorded.
		if v.logger != nil {
			v.logger.Error("client assertion could not be registered",
				slog.String("client_id", principal.ID),
				slog.String("reason", reasonRegistry),
				slog.String("error_type", fmt.Sprintf("%T", err)))
		}
		return ErrAuthenticationUnavailable
	}
}

// checkStateless runs every check that changes no state. It returns the
// expiry of the assertion and its identifier.
func (v *Verifier) checkStateless(ctx context.Context, options Options, principal Principal, audience string, assertion string) (*assertionHeader, time.Time, string, error) {
	if principal.ID == "" || assertion == "" || len(assertion) > options.MaxAssertionBytes {
		return nil, time.Time{}, "", reject(reasonStructure)
	}
	segments := strings.Split(assertion, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return nil, time.Time{}, "", reject(reasonStructure)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return nil, time.Time{}, "", reject(reasonStructure)
	}
	if _, err := base64.RawURLEncoding.DecodeString(segments[1]); err != nil {
		return nil, time.Time{}, "", reject(reasonStructure)
	}
	if _, err := base64.RawURLEncoding.DecodeString(segments[2]); err != nil {
		return nil, time.Time{}, "", reject(reasonStructure)
	}
	header := &assertionHeader{}
	if err := json.Unmarshal(rawHeader, header); err != nil {
		return nil, time.Time{}, "", reject(reasonStructure)
	}

	// The algorithm is settled from the header alone, before any key is
	// touched: it has to be one of the configured asymmetric algorithms.
	if !slices.Contains(options.SigningAlgorithms, header.Algorithm) || !slices.Contains(supportedSigningAlgorithms, header.Algorithm) {
		return header, time.Time{}, "", reject(reasonAlgorithm)
	}
	algorithm, known := jwa.LookupSignatureAlgorithm(header.Algorithm)
	if !known {
		return header, time.Time{}, "", reject(reasonAlgorithm)
	}
	if len(header.Critical) > 0 {
		return header, time.Time{}, "", reject(reasonStructure)
	}
	keyId := ""
	if header.KeyId != nil {
		keyId = *header.KeyId
	}

	publicKey, err := v.keys.verificationKey(ctx, principal, header.Algorithm, keyId)
	if err != nil {
		return header, time.Time{}, "", err
	}

	// Exactly this algorithm and exactly this key verify the signature.
	payload, err := jws.Verify([]byte(assertion), jws.WithKey(algorithm, publicKey))
	if err != nil {
		return header, time.Time{}, "", reject(reasonSignature)
	}

	expiresAt, identifier, err := checkClaims(payload, principal.ID, audience, v.clock.Now(), options)
	if err != nil {
		return header, time.Time{}, "", err
	}
	return header, expiresAt, identifier, nil
}

// checkClaims judges the claims of a verified assertion.
func checkClaims(payload []byte, id string, audience string, now time.Time, options Options) (time.Time, string, error) {
	var claims map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return time.Time{}, "", reject(reasonStructure)
	}

	if issuer, ok := stringClaim(claims["iss"]); !ok || issuer != id {
		return time.Time{}, "", reject(reasonIssuer)
	}
	if subject, ok := stringClaim(claims["sub"]); !ok || subject != id {
		return time.Time{}, "", reject(reasonSubject)
	}
	if !soleAudience(claims["aud"], audience) {
		return time.Time{}, "", reject(reasonAudience)
	}

	skew := options.ClockSkew
	expiresAt, present, ok := timeClaim(claims["exp"])
	if !present || !ok {
		return time.Time{}, "", reject(reasonExpired)
	}
	if !now.Before(expiresAt.Add(skew)) {
		return time.Time{}, "", reject(reasonExpired)
	}
	if expiresAt.Sub(now) > options.MaxAssertionLifetime {
		return time.Time{}, "", reject(reasonLifetime)
	}

	notBefore, present, ok := timeClaim(claims["nbf"])
	if present && (!ok || notBefore.After(now.Add(skew))) {
		return time.Time{}, "", reject(reasonNotBefore)
	}

	issuedAt, present, ok := timeClaim(claims["iat"])
	if present {
		if !ok || issuedAt.After(now.Add(skew)) {
			return time.Time{}, "", reject(reasonIssuedAt)
		}
		if now.Sub(issuedAt) > options.MaxAssertionLifetime+skew {
			return time.Time{}, "", reject(reasonIssuedAt)
		}
	}

	identifier, ok := stringClaim(claims["jti"])
	if !ok || identifier == "" || len(identifier) > maxAssertionIdBytes {
		return time.Time{}, "", reject(reasonIdentifier)
	}
	return expiresAt, identifier, nil
}

// stringClaim reads a claim that has to be a JSON string.
func stringClaim(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// soleAudience reports whether the aud claim names the authorization
// server's issuer identifier and nothing else: either the string itself, or
// an array holding exactly that one string. The comparison is byte for byte.
func soleAudience(raw json.RawMessage, audience string) bool {
	if audience == "" {
		return false
	}
	if value, ok := stringClaim(raw); ok {
		return value == audience
	}
	var values []json.RawMessage
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &values) != nil || len(values) != 1 {
		return false
	}
	value, ok := stringClaim(values[0])
	return ok && value == audience
}

// timeClaim reads a numeric date claim. present is false when the claim is
// absent; ok is false when it is not a finite JSON number within the
// representable range. Fractions are cut off towards the earlier second.
func timeClaim(raw json.RawMessage) (value time.Time, present bool, ok bool) {
	if len(raw) == 0 {
		return time.Time{}, false, false
	}
	var number json.Number
	if raw[0] == '"' || json.Unmarshal(raw, &number) != nil {
		return time.Time{}, true, false
	}
	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > maxNumericDateSeconds {
		return time.Time{}, true, false
	}
	return time.Unix(int64(math.Floor(seconds)), 0), true, true
}

// logRejection records why an assertion was rejected. The assertion, its
// signature and its identifier are never part of the record.
func (v *Verifier) logRejection(principal Principal, header *assertionHeader, reason string) {
	if v.logger == nil {
		return
	}
	attributes := []any{slog.String("client_id", principal.ID), slog.String("reason", reason)}
	if header != nil {
		attributes = append(attributes, slog.String("alg", truncate(header.Algorithm, 16)))
		if header.KeyId != nil {
			attributes = append(attributes, slog.String("kid", truncate(*header.KeyId, maxLoggedKeyIdBytes)))
		}
	}
	v.logger.Warn("client assertion rejected", attributes...)
}

func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
