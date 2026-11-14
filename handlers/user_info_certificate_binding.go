// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package handlers

import (
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/gonewx/wicket"
	"github.com/gonewx/wicket/certbind"
	"github.com/gonewx/wicket/claims"
)

// ClientCertificateSource yields the client certificates presented with a
// request, the leaf first, or nil when the request carries none.
type ClientCertificateSource interface {
	ClientCertificates(request *http.Request) []*x509.Certificate
}

// errMultipleConfirmations reports a token carrying more than one cnf claim.
var errMultipleConfirmations = errors.New("token carries more than one confirmation")

// SetClientCertificateSource sets where the userinfo endpoint reads the
// client certificate a certificate bound access token is checked against.
// Nil reads the peer certificates of the TLS connection.
func (h *UserInfoHandler) SetClientCertificateSource(source ClientCertificateSource) {
	h.certificates = source
}

func (h *UserInfoHandler) clientCertificates(r *http.Request) []*x509.Certificate {
	if h.certificates != nil {
		return h.certificates.ClientCertificates(r)
	}
	if r == nil || r.TLS == nil {
		return nil
	}
	return r.TLS.PeerCertificates
}

// checkCertificateBinding verifies that a token bound to a client
// certificate (RFC 8705 §3) is presented with that certificate. A token
// without a cnf claim passes; a malformed or repeated cnf fails.
func (h *UserInfoHandler) checkCertificateBinding(r *http.Request, tokenClaims []*claims.Claim) error {
	var cnf []any
	for _, claim := range tokenClaims {
		if claim != nil && claim.Type == wicket.JwtClaimTypesConfirmation {
			cnf = append(cnf, claim.Value)
		}
	}
	switch len(cnf) {
	case 0:
		return nil
	case 1:
		if cnf[0] == nil {
			// A cnf claim that is present but null is not a confirmation.
			return certbind.ErrMalformedConfirmation
		}
		return certbind.Check(cnf[0], h.clientCertificates(r))
	default:
		return errMultipleConfirmations
	}
}
