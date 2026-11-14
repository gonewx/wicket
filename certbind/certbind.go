// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package certbind

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// ThumbprintMember is the confirmation member holding the certificate
// thumbprint.
const ThumbprintMember = "x5t#S256"

var (
	// ErrMalformedConfirmation reports a confirmation value that is neither
	// absent nor a JSON object whose x5t#S256 member, when present, is a
	// non-empty string.
	ErrMalformedConfirmation = errors.New("certbind: malformed confirmation")
	// ErrCertificateMissing reports a certificate bound token presented
	// without a client certificate.
	ErrCertificateMissing = errors.New("certbind: client certificate missing")
	// ErrCertificateMismatch reports a certificate bound token presented with
	// a client certificate other than the one it is bound to.
	ErrCertificateMismatch = errors.New("certbind: client certificate does not match the confirmation")
)

// Thumbprint returns the x5t#S256 thumbprint of certificate: the unpadded
// base64url encoding of the SHA-256 digest of its DER encoding.
func Thumbprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// Confirmation returns the JSON text of the confirmation binding a token to
// certificate, {"x5t#S256":"<thumbprint>"}.
func Confirmation(certificate *x509.Certificate) string {
	encoded, _ := json.Marshal(map[string]string{ThumbprintMember: Thumbprint(certificate)})
	return string(encoded)
}

// Check verifies the presented certificates against a token's cnf value. A
// nil cnf, or a cnf object without an x5t#S256 member, does not bind the
// token to a certificate and passes. cnf may be a map[string]any or its JSON
// text; any other shape, or an x5t#S256 member that is not a non-empty
// string, yields ErrMalformedConfirmation. A bound token presented without a
// certificate (no certificates, or a nil leaf) yields ErrCertificateMissing,
// and one whose leaf certificate has another thumbprint yields
// ErrCertificateMismatch.
func Check(cnf any, certificates []*x509.Certificate) error {
	if cnf == nil {
		return nil
	}
	var members map[string]any
	switch value := cnf.(type) {
	case map[string]any:
		members = value
	case string:
		if err := json.Unmarshal([]byte(value), &members); err != nil || members == nil {
			return ErrMalformedConfirmation
		}
	default:
		return ErrMalformedConfirmation
	}
	raw, bound := members[ThumbprintMember]
	if !bound {
		return nil
	}
	expected, ok := raw.(string)
	if !ok || expected == "" {
		return ErrMalformedConfirmation
	}
	if len(certificates) == 0 || certificates[0] == nil {
		return ErrCertificateMissing
	}
	if subtle.ConstantTimeCompare([]byte(Thumbprint(certificates[0])), []byte(expected)) != 1 {
		return ErrCertificateMismatch
	}
	return nil
}
