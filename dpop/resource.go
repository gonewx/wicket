// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

// accessTokenHashClaim is the proof claim carrying the hash of the access
// token presented with it (RFC 9449 section 4.2).
const accessTokenHashClaim = "ath"

// ErrMalformedConfirmation reports a cnf value that is neither absent nor a
// JSON object whose jkt member, when present, is a non-empty string.
var ErrMalformedConfirmation = errors.New("dpop: malformed confirmation")

// AccessTokenHash returns the ath value of accessToken: the unpadded
// base64url encoding of the SHA-256 digest of its ASCII bytes.
func AccessTokenHash(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// VerifyForResource checks the DPoP header values of a request presenting
// accessToken to a protected resource. It runs every check Verify runs and
// then requires the ath claim to be a JSON string equal to
// AccessTokenHash(accessToken); a missing, non-string or different ath, or
// an empty accessToken, yields an error matching ErrInvalidProof. Whether
// the proof key is the one the token is bound to is left to the caller, see
// ConfirmationThumbprint and ThumbprintMatches.
func (v *Verifier) VerifyForResource(values []string, method string, endpoint string, accessToken string, now time.Time) (Proof, error) {
	proof, claims, err := v.verify(values, method, endpoint, now)
	if err != nil {
		return Proof{}, err
	}
	if accessToken == "" {
		return Proof{}, invalid("ath")
	}
	ath, ok := stringMember(claims[accessTokenHashClaim])
	if !ok || subtle.ConstantTimeCompare([]byte(ath), []byte(AccessTokenHash(accessToken))) != 1 {
		return Proof{}, invalid("ath")
	}
	return proof, nil
}

// ConfirmationThumbprint reads the proof key thumbprint a token's cnf value
// binds it to. cnf may be a map[string]any or its JSON text. A nil cnf, or
// a cnf object without a jkt member, does not bind the token to a proof key:
// bound is false and err nil. Any other shape, JSON text that is not an
// object, or a jkt member that is not a non-empty string yields
// ErrMalformedConfirmation.
func ConfirmationThumbprint(cnf any) (thumbprint string, bound bool, err error) {
	if cnf == nil {
		return "", false, nil
	}
	var members map[string]any
	switch value := cnf.(type) {
	case map[string]any:
		members = value
	case string:
		if err := json.Unmarshal([]byte(value), &members); err != nil || members == nil {
			return "", false, ErrMalformedConfirmation
		}
	default:
		return "", false, ErrMalformedConfirmation
	}
	raw, present := members[ConfirmationMember]
	if !present {
		return "", false, nil
	}
	thumbprint, ok := raw.(string)
	if !ok || thumbprint == "" {
		return "", false, ErrMalformedConfirmation
	}
	return thumbprint, true, nil
}

// ThumbprintMatches reports, in constant time, whether proof was signed with
// the key whose thumbprint is given. An empty thumbprint never matches.
func ThumbprintMatches(proof Proof, thumbprint string) bool {
	if thumbprint == "" || proof.Thumbprint == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(proof.Thumbprint), []byte(thumbprint)) == 1
}
