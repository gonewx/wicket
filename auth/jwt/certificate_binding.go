// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package jwt

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/gonewx/wicket/certbind"
)

// CertificateSource yields the client certificates presented with a request,
// the leaf first, or nil when the request carries none.
type CertificateSource interface {
	ClientCertificates(request *http.Request) []*x509.Certificate
}

// ErrCertificateBindingMismatch fails the authentication of a certificate
// bound access token (RFC 8705 §3) that is not presented with the client
// certificate it is bound to, or whose confirmation is malformed.
var ErrCertificateBindingMismatch = errors.New("jwt: access token is not presented with the client certificate it is bound to")

// confirmationClaim is the JWT claim holding a token's confirmation.
const confirmationClaim = "cnf"

// certificateBindingError checks a validated token against the client
// certificate of the request while Options.CertificateBindingSource is set,
// and returns nil when it is not. A token without a cnf claim passes; a
// token whose claims cannot be read is treated as a mismatch.
func (h *Handler) certificateBindingError(r *http.Request, token SecurityToken) error {
	source := h.Options.CertificateBindingSource
	if source == nil {
		return nil
	}
	validated, ok := token.(*validatedToken)
	if !ok || validated == nil || validated.token == nil {
		return ErrCertificateBindingMismatch
	}
	if !validated.token.Has(confirmationClaim) {
		return nil
	}
	var cnf any
	if err := validated.token.Get(confirmationClaim, &cnf); err != nil || cnf == nil {
		return ErrCertificateBindingMismatch
	}
	if err := certbind.Check(cnf, source.ClientCertificates(r)); err != nil {
		return fmt.Errorf("%w: %w", ErrCertificateBindingMismatch, err)
	}
	return nil
}
