// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"crypto/x509"
	"net/http"
	"slices"
)

// CertificateSource yields the client certificates presented with a
// request, the leaf first and any intermediates after it. It returns nil
// when the request carries no client certificate.
type CertificateSource interface {
	ClientCertificates(request *http.Request) []*x509.Certificate
}

// ConnectionCertificateSource reads the certificates the peer presented on
// the TLS connection the request arrived on.
type ConnectionCertificateSource struct{}

var _ CertificateSource = ConnectionCertificateSource{}

// ClientCertificates returns the peer certificates of the request's TLS
// connection, or nil for a request without TLS or without peer
// certificates.
func (ConnectionCertificateSource) ClientCertificates(request *http.Request) []*x509.Certificate {
	if request == nil || request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return nil
	}
	return slices.Clone(request.TLS.PeerCertificates)
}

// Options configures mutual TLS client authentication.
type Options struct {
	// TrustedAuthorities holds the root certificates a tls_client_auth
	// certificate chain must end in. While it is nil the tls_client_auth
	// method is unavailable and only self_signed_tls_client_auth can be used.
	TrustedAuthorities *x509.CertPool
}
