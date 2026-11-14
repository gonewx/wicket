// Copyright 2026 Decker.
// Licensed under the Apache License, Version 2.0.

package clientcert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConnectionCertificateSourceReadsTheHandshake(t *testing.T) {
	now := time.Now()
	client := issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "handshake-client"},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}, nil)

	seen := make(chan []*x509.Certificate, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- ConnectionCertificateSource{}.ClientCertificates(r)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	server.StartTLS()
	t.Cleanup(server.Close)

	get := func(t *testing.T, certificates []tls.Certificate) []*x509.Certificate {
		t.Helper()
		transport := server.Client().Transport.(*http.Transport).Clone()
		transport.TLSClientConfig.Certificates = certificates
		response, err := (&http.Client{Transport: transport}).Get(server.URL)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		_ = response.Body.Close()
		return <-seen
	}

	presented := get(t, []tls.Certificate{{Certificate: [][]byte{client.cert.Raw}, PrivateKey: client.key}})
	if len(presented) != 1 || !bytes.Equal(presented[0].Raw, client.cert.Raw) {
		t.Fatalf("source returned %d certificates, want the presented leaf", len(presented))
	}

	if absent := get(t, nil); absent != nil {
		t.Fatalf("request without a client certificate: %v, want nil", absent)
	}
}
