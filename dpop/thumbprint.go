// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package dpop

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ConfirmationMember is the confirmation member holding the proof key
// thumbprint.
const ConfirmationMember = "jkt"

// Thumbprint returns the JWK thumbprint (RFC 7638) of key: the SHA-256
// digest of its required members in canonical JSON form, as unpadded
// base64url.
func Thumbprint(key jwk.Key) (string, error) {
	if key == nil {
		return "", errors.New("dpop: no key")
	}
	digest, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(digest), nil
}

// Confirmation returns the JSON text of the confirmation binding a token to
// the proof key with thumbprint, {"jkt":"<thumbprint>"}.
func Confirmation(thumbprint string) string {
	encoded, _ := json.Marshal(map[string]string{ConfirmationMember: thumbprint})
	return string(encoded)
}

// proofContextKey is the context key of the proof key thumbprint.
type proofContextKey struct{}

// WithProof returns a context carrying the thumbprint of the key of the
// proof accepted for the current request. An empty thumbprint returns ctx
// unchanged.
func WithProof(ctx context.Context, thumbprint string) context.Context {
	if thumbprint == "" {
		return ctx
	}
	return context.WithValue(ctx, proofContextKey{}, thumbprint)
}

// ProofThumbprint returns the proof key thumbprint ctx carries, or "" when
// the request presented no accepted proof.
func ProofThumbprint(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	thumbprint, _ := ctx.Value(proofContextKey{}).(string)
	return thumbprint
}
